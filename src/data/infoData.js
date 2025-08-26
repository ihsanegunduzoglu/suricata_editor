// Bu dosya, editördeki alanlar için yardım metinlerini içerir.
// Bilgiler Suricata dokümantasyonundan özetlenmiştir.

export const infoData = {
    'Action': {
        title: 'Eylem (Action)',
        description: 'Bir kural tetiklendiğinde Suricata\'nın ne yapacağını belirler. Kuralın en başındaki zorunlu alandır.',
        options: [
            { name: 'alert', detail: 'Bir uyarı oluşturur ve paketi işlemeye devam eder.' },
            { name: 'pass', detail: 'Paketin geri kalan kuralları kontrol etmesini engeller ve kabul eder.' },
            { name: 'drop', detail: 'Paketi anında durdurur, göndericiye veya alıcıya bilgi vermez (inline/IPS modunda).' },
            { name: 'reject', detail: 'Paketi reddeder ve hem göndericiye (ICMP hata) hem de alıcıya (TCP reset) bilgi gönderir.' }
        ]
    },
    'Protocol': {
        title: 'Protokol',
        description: 'Kuralın hangi ağ protokolü için geçerli olacağını belirtir.',
        options: [
            { name: 'tcp', detail: 'TCP trafiği için (örn: HTTP, FTP).' },
            { name: 'udp', detail: 'UDP trafiği için (örn: DNS, bazı oyunlar).' },
            { name: 'icmp', detail: 'ICMP trafiği için (örn: ping istekleri).' },
            { name: 'ip', detail: 'Tüm IP tabanlı trafikler için geçerlidir.' }
        ]
    },
    'Source IP': {
        title: 'Kaynak IP Adresi',
        description: 'Kuralın hangi kaynak IP adresinden gelen trafik için tetikleneceğini tanımlar. Değişkenler (örn: $HOME_NET), tek IP, IP bloğu (CIDR) veya "any" (herhangi) kullanılabilir.'
    },
    'Source Port': {
        title: 'Kaynak Port',
        description: 'Kuralın hangi kaynak porttan gelen trafik için tetikleneceğini tanımlar. Tek port, port aralığı (örn: 1024:65535) veya "any" kullanılabilir.'
    },
    'Direction': {
        title: 'Yön Operatörü',
        description: 'Trafiğin akış yönünü belirtir. Kaynaktan hedefe doğru mu, yoksa iki yönlü mü olduğunu tanımlar.',
        options: [
            { name: '->', detail: 'Trafik, Kaynak IP/Port\'tan Hedef IP/Port\'a doğru tek yönlü olarak incelenir.' },
            { name: '<>', detail: 'Trafik, iki IP/Port arasında çift yönlü olarak incelenir.' }
        ]
    },
    'Destination IP': {
        title: 'Hedef IP Adresi',
        description: 'Kuralın hangi hedef IP adresine giden trafik için tetikleneceğini tanımlar. Değişkenler, tek IP, IP bloğu (CIDR) veya "any" kullanılabilir.'
    },
    'Destination Port': {
        title: 'Hedef Port',
        description: 'Kuralın hangi hedef porta giden trafik için tetikleneceğini tanımlar. Tek port, port aralığı veya "any" kullanılabilir.'
    }
};