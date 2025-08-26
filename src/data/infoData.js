// src/data/infoData.js

export const infoData = {
    // ======================================================
    // Kural Başlığı (Header) Bilgileri
    // ======================================================
    'Action': {
        title: 'Eylem (Action)',
        summary: 'Bir kural tetiklendiğinde Suricata\'nın ne yapacağını belirler.',
        details: 'Bu, bir kuralın en temel parçasıdır ve paketin akıbetini tanımlar. IPS modunda `drop` ve `reject` gibi eylemler trafiği aktif olarak engellerken, IDS modunda sadece `alert` ve `pass` anlamlıdır.',
        syntax: 'alert | pass | drop | reject',
        example: 'alert tcp any any -> any any (msg:"TCP Paketi Tespit Edildi";)',
        options: [
            { name: 'alert', detail: 'Bir uyarı oluşturur ve paketi işlemeye devam eder.' },
            { name: 'pass', detail: 'Paketin geri kalan kuralları kontrol etmesini engeller ve kabul eder.' },
            { name: 'drop', detail: 'Paketi anında durdurur, göndericiye veya alıcıya bilgi vermez (inline/IPS modunda).' },
            { name: 'reject', detail: 'Paketi reddeder ve hem göndericiye (ICMP hata) hem de alıcıya (TCP reset) bilgi gönderir.' }
        ]
    },
    'Protocol': {
        title: 'Protokol',
        summary: 'Kuralın hangi ağ protokolü için geçerli olacağını belirtir.',
        details: 'Protokolü ne kadar spesifik belirtirseniz, kuralın performansı o kadar artar. Örneğin, sadece web trafiğini incelemek istiyorsanız `http` kullanmak, genel `tcp` kullanmaktan daha verimlidir.',
        syntax: 'tcp | udp | icmp | ip | http | ftp | tls | ...',
        example: 'alert http $HOME_NET any -> $EXTERNAL_NET 80 (...)'
    },
    'Source IP': {
        title: 'Kaynak IP Adresi',
        summary: 'Trafiğin başlangıç noktasını (kaynağını) tanımlar.',
        details: '`suricata.yaml` dosyasında tanımlanan değişkenleri ($HOME_NET, $EXTERNAL_NET) kullanmak, kuralları daha taşınabilir ve yönetilebilir hale getirir. IP adreslerini `!` karakteri ile hariç tutabilirsiniz.',
        syntax: 'any | $HOME_NET | 192.168.1.10 | ![1.1.1.1, 1.1.1.2] | 10.0.0.0/24',
        example: 'alert tcp !$HOME_NET any -> $HOME_NET 22 (...)'
    },
    'Source Port': {
        title: 'Kaynak Port',
        summary: 'Trafiğin kaynak portunu belirtir.',
        details: 'Genellikle istemci tarafında rastgele (efemeral) portlar kullanıldığı için kaynak portu `any` olarak bırakmak yaygındır. Ancak belirli bir kaynaktan gelen özel bir trafiği hedefliyorsanız spesifik portlar kullanışlı olabilir.',
        syntax: 'any | 80 | !80 | 1024: | :1024 | 1024:65535',
        example: 'alert udp any 1024: -> $HOME_NET 53 (...)'
    },
    'Direction': {
        title: 'Yön Operatörü',
        summary: 'Trafiğin akış yönünü belirtir.',
        details: 'Tek yönlü (`->`) operatör en sık kullanılanıdır ve kuralın sadece belirtilen yönde çalışmasını sağlar. Çift yönlü (`<>`) ise her iki tarafın da hem kaynak hem de hedef olabileceği durumlarda kullanılır.',
        syntax: '-> | <>',
        example: 'alert tcp $HOME_NET any <> $EXTERNAL_NET 80 (...)'
    },
    'Destination IP': {
        title: 'Hedef IP Adresi',
        summary: 'Trafiğin bitiş noktasını (hedefini) tanımlar.',
        details: 'Genellikle dış ağdaki bilinen bir sunucu veya iç ağdaki korunması gereken bir sunucu belirtilir. Kaynak IP gibi, burada da değişkenler, tek IP, IP bloğu veya "any" kullanılabilir.',
        syntax: 'any | $EXTERNAL_NET | 8.8.8.8 | 192.168.1.0/24',
        example: 'alert tcp $HOME_NET any -> 8.8.8.8 53 (...)'
    },
    'Destination Port': {
        title: 'Hedef Port',
        summary: 'Trafiğin hedef portunu belirtir.',
        details: 'Genellikle bilinen servis portları (HTTP için 80, SSH için 22 vb.) burada belirtilir. Birçok portu veya port aralığını virgülle ayırarak veya köşeli parantez içinde belirtebilirsiniz.',
        syntax: 'any | 80 | [80,443] | ![21,22,23]',
        example: 'alert tcp $HOME_NET any -> $EXTERNAL_NET [80,8080]'
    },

    // ======================================================
    // Kural Seçenekleri (Options) Bilgileri - DETAYLANDIRILMIŞ
    // ======================================================
    'msg': { 
        title: 'msg (Message)', 
        summary: 'Kural tetiklendiğinde üretilecek uyarı mesajını belirtir.',
        details: '`msg` (mesaj), loglarda ve uyarılarda görünecek olan metindir. Kuralın neyi tespit ettiğini açık ve anlaşılır bir şekilde ifade etmelidir. Her kuralda bulunması zorunludur.',
        syntax: 'msg:"<mesaj metni>";',
        example: 'msg:"ET TROJAN Win32/Sirefef.PUP Gen";'
    },
    'sid': { 
        title: 'sid (Signature ID)', 
        summary: 'Kural için benzersiz bir kimlik numarasıdır.',
        details: '`sid` (imza kimliği), her kuralı benzersiz bir şekilde tanımlar. Kural yönetim araçları (rule management) tarafından kullanılır. Yerel olarak oluşturulan kurallar için genellikle 1,000,000 ile 1,999,999 arası numaralar kullanılır. Her kuralda bulunması zorunludur.',
        syntax: 'sid:<benzersiz numara>;',
        example: 'sid:1000001;'
    },
    'rev': { 
        title: 'rev (Revision)', 
        summary: 'Kuralın revizyon numarasını belirtir.',
        details: '`rev` (revizyon), kuralda her değişiklik yapıldığında artırılması gereken bir versiyon numarasıdır. Kuralın zaman içindeki değişimini takip etmeyi sağlar.',
        syntax: 'rev:<versiyon numarası>;',
        example: 'rev:1;'
    },
    'flow': { 
        title: 'flow (Akış Durumu)', 
        summary: 'Kuralın sadece belirli TCP bağlantı durumlarındaki trafik için geçerli olmasını sağlar.',
        details: '`flow`, bir TCP oturumunun durumunu kontrol ederek kuralın ne zaman çalışacağını belirler. Bu, gereksiz kontrolleri önleyerek performansı önemli ölçüde artırır.',
        syntax: 'flow:to_client | to_server | established | not_established | ... ;',
        example: 'flow:established,to_server;',
        // YENİ: Sağ panelde de detaylı gösterebilmek için options ekliyoruz
        options: [
            { name: 'established', detail: 'Üçlü el sıkışması tamamlanmış, aktif TCP bağlantıları.' },
            { name: 'to_client', detail: 'Trafiğin sunucudan istemciye doğru aktığı yönü belirtir.' },
            { name: 'from_server', detail: '`to_client` ile aynı anlama gelir.' },
            { name: 'not_established', detail: 'Henüz üçlü el sıkışması tamamlanmamış bağlantılar (örn: sadece SYN paketi).' },
        ]
    },
    'content': { 
        title: 'content (İçerik)', 
        summary: 'Paket içeriğinde (payload) aranacak olan metni veya hexadecimal veriyi belirtir.',
        details: '`content`, bir kuralın en güçlü parçalarından biridir. Belirtilen metni veya byte dizisini paket içeriğinde arar. Daha verimli hale getirmek için `depth`, `offset`, `distance` gibi diğer anahtar kelimelerle birlikte kullanılır.',
        syntax: 'content:"<aranacak metin>";',
        example: 'content:"|00 01 86 a5|";'
    },
    'http_uri': {
        title: 'http_uri',
        summary: 'Bir "content" aramasının sadece URI\'da yapılmasını sağlar.',
        details: 'Bu bir "sticky buffer"dır. Kendisinden sonra gelen ilk `content` aramasının, paketin tamamı yerine sadece HTTP isteğinin URI (örn: /index.php?id=123) bölümünde yapılmasını zorunlu kılar. Performansı artırır.',
        syntax: 'http_uri; content:"/admin";',
        example: 'alert http any any -> any 80 (http_uri; content:"/malware.exe"; ...);'
    },
    'nocase': { 
        title: 'nocase (Büyük/Küçük Harf Duyarsız)', 
        summary: 'Bir "content" aramasını büyük/küçük harf duyarsız yapar.',
        details: '`nocase`, kendisinden önce gelen `content` aramasının büyük/küçük harf ayrımı yapmadan gerçekleştirilmesini sağlar. Özellikle metin tabanlı protokollerde kullanışlıdır.',
        syntax: 'content:"evil"; nocase;',
        example: 'content:"GET"; nocase; // "GET", "get", "Get" vb. hepsiyle eşleşir'
    },
    'depth': { 
        title: 'depth (Derinlik)', 
        summary: 'Aramanın, paket içeriğinin (payload) başından itibaren kaç byte içinde yapılacağını belirtir.',
        details: '`depth`, kendisinden önce gelen `content` aramasının ne kadar derine inileceğini sınırlar. Örneğin, bir ifadenin sadece ilk 10 byte içinde olup olmadığını kontrol etmek, tüm paketi taramaktan çok daha hızlıdır.',
        syntax: 'content:"<metin>"; depth:<byte sayısı>;',
        example: 'content:"MZ"; depth:2; // Sadece ilk 2 byte içinde "MZ" (PE header) ara'
    },
    'offset': { 
        title: 'offset (Başlangıç)', 
        summary: 'Aramanın, paket içeriğinin (payload) kaçıncı byte\'ından sonra başlayacağını belirtir.',
        details: '`offset`, `content` aramasının başlayacağı noktayı belirler. Bu, bilinen bir protokol yapısında belirli bir alandaki veriyi kontrol etmek için kullanılır.',
        syntax: 'content:"<metin>"; offset:<byte sayısı>;',
        example: 'content:"evil"; offset:10; // Aramaya 10. byte\'tan sonra başla'
    },
};