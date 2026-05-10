package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/proxy"
)

// Konfigurasi Konstanta
const (
	MongoURI       = "mongodb://localhost:27017"
	DatabaseName   = "osint_tor"
	CollectionName = "onion_sites"
	TorProxyURL    = "127.0.0.1:9150" // Port Tor telah diubah ke 9150
	NumWorkers     = 20               // Jumlah goroutines paralel (sesuaikan dengan kemampuan jaringan/RAM)
	RequestTimeout = 60 * time.Second // Tor sangat lambat, butuh timeout panjang
)

// OnionData merepresentasikan struktur dokumen di MongoDB
type OnionData struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	URL          string             `bson:"url"`
	DiscoveredAt time.Time          `bson:"discovered_at"`
	RawHTML      string             `bson:"raw_html"`
	CleanText    string             `bson:"clean_text"`
	Status       string             `bson:"status"` // "pending", "processing_ai", "completed", "error", "scraped"
}

// Global Variables
var db *mongo.Collection
var ctx = context.Background()

func main() {
	// 1. Inisialisasi Koneksi MongoDB
	clientOptions := options.Client().ApplyURI(MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Gagal connect MongoDB: %v", err)
	}
	defer client.Disconnect(ctx)

	db = client.Database(DatabaseName).Collection(CollectionName)
	fmt.Println("Berhasil terhubung ke MongoDB!")

	// Cek koneksi ke Tor Proxy sebelum memulai crawler
	fmt.Printf("Mengecek koneksi ke Tor Proxy di %s...\n", TorProxyURL)
	if err := checkTorProxy(); err != nil {
		log.Fatalf("Tor Proxy tidak aktif di %s.\nError: %v\nSilakan nyalakan Tor terlebih dahulu sebelum menjalankan crawler!", TorProxyURL, err)
	}
	fmt.Println("Tor Proxy terdeteksi aktif!")

	// Buat index URL agar tidak ada duplikasi data
	createIndex()

	// 2. Persiapkan Worker Pool
	var wg sync.WaitGroup
	// Channel untuk mengirim URL yang akan discrape ke worker
	jobs := make(chan string, 100)

	// Jalankan Worker
	for w := 1; w <= NumWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, &wg)
	}

	// 3. Masukkan Seed URL (Titik awal crawling)
	// Anda bisa mengganti ini dengan URL onion asli jika Anda punya
	seedURLs := []string{
		"http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion",                          // Contoh (Mungkin tidak aktif)
		"http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page", // The Hidden Wiki
		"http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/top_onions",               //tor66
		"http://gszionb5csgn24c2siowqzwj4bipigtvcs754hepe3ls3hf7qpcdxaqd.onion/",                         //cavetor
		"http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/",                         //everest group
	}

	for _, u := range seedURLs {
		insertPendingURL(u)
	}

	// 4. Polling Loop: Ambil URL dengan status "pending" dan kirim ke jobs
	fmt.Println("Memulai Harvester Polling Loop...")
	for {
		var doc OnionData
		// Cari satu dokumen yang masih pending dan ubah statusnya menjadi "scraped" (agar tidak diambil worker lain)
		err := db.FindOneAndUpdate(
			ctx,
			bson.M{"status": "pending"},
			bson.M{"$set": bson.M{"status": "scraped"}},
		).Decode(&doc)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				// Jika tidak ada URL pending, tunggu sebentar lalu cek lagi
				fmt.Println("Menunggu URL baru...")
				time.Sleep(10 * time.Second)
				continue
			}
			log.Printf("Error saat mengambil dokumen pending: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Kirim URL ke channel untuk dikerjakan worker
		jobs <- doc.URL
	}

	// wg.Wait() // Dalam kasus ini loop berjalan selamanya
}

// checkTorProxy memastikan port SOCKS5 Tor terbuka dan siap menerima koneksi
func checkTorProxy() error {
	conn, err := net.DialTimeout("tcp", TorProxyURL, 3*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// worker adalah goroutine yang melakukan HTTP Request lewat Tor
func worker(id int, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Setup Tor Client
	dialer, err := proxy.SOCKS5("tcp", TorProxyURL, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Worker %d: Gagal setup Tor proxy: %v", id, err)
	}
	tr := &http.Transport{Dial: dialer.Dial}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   RequestTimeout,
	}

	for urlTarget := range jobs {
		fmt.Printf("Worker %d memproses: %s\n", id, urlTarget)

		// 1. Fetch HTML
		req, err := http.NewRequest("GET", urlTarget, nil)
		if err != nil {
			markError(urlTarget, err.Error())
			continue
		}
		// Beberapa situs memblokir crawler, gunakan User-Agent standar
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			markError(urlTarget, fmt.Sprintf("Gagal request HTTP: %v", err))
			continue
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			markError(urlTarget, fmt.Sprintf("Gagal baca body: %v", err))
			continue
		}
		rawHTML := string(bodyBytes)

		// 2. Pre-processing: Ekstrak Teks Bersih & Temukan URL Baru
		cleanText, newURLs := processHTML(rawHTML, urlTarget)

		// 3. Masukkan URL baru yang ditemukan ke Database (sebagai pending)
		for _, nu := range newURLs {
			insertPendingURL(nu)
		}

		// 4. Update dokumen di database dengan hasil scrape
		_, err = db.UpdateOne(
			ctx,
			bson.M{"url": urlTarget},
			bson.M{
				"$set": bson.M{
					"raw_html":   rawHTML,
					"clean_text": cleanText,
					"status":     "processing_ai", // Siap untuk diambil oleh worker AI
				},
			},
		)
		if err != nil {
			log.Printf("Worker %d: Gagal update DB untuk %s: %v\n", id, urlTarget, err)
		} else {
			fmt.Printf("Worker %d: Selesai %s. Ditemukan %d link baru.\n", id, urlTarget, len(newURLs))
		}
	}
}

// processHTML membuang tag HTML dan mengekstrak semua tautan .onion baru
func processHTML(htmlContent string, sourceURL string) (string, []string) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return "", nil
	}

	// Hapus script dan style agar teks lebih bersih
	doc.Find("script, style, iframe, noscript").Remove()
	cleanText := strings.TrimSpace(doc.Text())

	// Sederhanakan whitespace yang berlebihan
	cleanText = strings.Join(strings.Fields(cleanText), " ")

	var extractedURLs []string
	baseURL, _ := url.Parse(sourceURL)

	// Cari semua tag <a>
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			// Resolve relative URL (contoh: href="/about.html" menjadi http://xxx.onion/about.html)
			parsedHref, err := url.Parse(href)
			if err == nil {
				absoluteURL := baseURL.ResolveReference(parsedHref).String()
				// Hanya ambil link yang berakhiran .onion
				if strings.Contains(absoluteURL, ".onion") {
					// Hapus fragment (#) dari URL
					cleanURL := strings.Split(absoluteURL, "#")[0]
					extractedURLs = append(extractedURLs, cleanURL)
				}
			}
		}
	})

	return cleanText, extractedURLs
}

// insertPendingURL memasukkan URL ke DB jika belum ada
func insertPendingURL(targetURL string) {
	// Abaikan file statis untuk menghemat resource
	if strings.HasSuffix(targetURL, ".jpg") || strings.HasSuffix(targetURL, ".png") || strings.HasSuffix(targetURL, ".css") {
		return
	}

	doc := OnionData{
		URL:          targetURL,
		DiscoveredAt: time.Now(),
		Status:       "pending",
	}

	// UpdateOpts dengan Upsert=true akan insert jika tidak ada, atau abaikan jika sudah ada (karena index unique)
	opts := options.Update().SetUpsert(true)
	filter := bson.M{"url": targetURL}
	update := bson.M{"$setOnInsert": doc} // Hanya set value jika dokumen baru

	_, err := db.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		// Log error diabaikan agar console tidak berisik karena duplicate key error
		// fmt.Printf("Gagal insert URL %s: %v\n", targetURL, err)
	}
}

func markError(urlTarget string, errorMsg string) {
	log.Printf("Error pada %s: %s\n", urlTarget, errorMsg)
	db.UpdateOne(
		ctx,
		bson.M{"url": urlTarget},
		bson.M{"$set": bson.M{"status": "error", "raw_html": errorMsg}},
	)
}

func createIndex() {
	indexModel := mongo.IndexModel{
		Keys:    bson.D{bson.E{Key: "url", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err := db.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		log.Printf("Peringatan: Gagal membuat index unik: %v\n", err)
	}
}
