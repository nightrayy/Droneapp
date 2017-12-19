#include "snifferworker.h"
#include <QDebug>
#include <QMessageBox>
//------------------------------------------------------------------
SnifferWorker::SnifferWorker()
{
    buf = new unsigned char[65536]; // ustawienie bufora na przechwycone pakiety
}
//------------------------------------------------------------------
SnifferWorker::~SnifferWorker()
{
    delete [] buf;
    if (raw_sock >= 0) {
        close(raw_sock);
    }
}
//------------------------------------------------------------------
void SnifferWorker::doSniff() {
    qDebug() << "sniffer-worker!!!";
    //clear packets counters & txt
    pc.etc=pc.icmp=pc.igmp=pc.tcp=pc.udp=pc.all = 0;
    packetstxt.clear();
    //create and init raw socket
    if (raw_sock >= 0) {
        close(raw_sock);
        raw_sock = -1;
    }
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // zbieranie wszystkich pakietow
    if (raw_sock < 0) {
        emit snifferError("Problem with raw socket");
        emit finished();
        return;
    }

    sockaddr saddr;
    working = true;


    while (working) {
        //capture packet
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(raw_sock, buf, 65536, 0, &saddr, (socklen_t*)&saddr_size);
//        qDebug() << " rozmiar to " << data_size;
        //QThread::msleep(100); -- do testów
        //decode packet
        if (data_size < 0) {
            emit snifferError("recvfrom error");
            close(raw_sock);
            raw_sock = -1;
            emit finished();
            return;
        }
        //tutaj
        //emit capturedPacket("packet " + QString::number(data_size));

        packetstxt.clear();

        //decode packet type
        // Pobranie czesci IP header z pakietu
        iphdr *iph = (iphdr*)(buf + sizeof(struct ethhdr));
        pc.all++;
        switch (iph->protocol) //sprawdzenie rodzaju protokolu pakietow
        {
            case 1:  //protokol icmp ( wykorzystywany w diagnostyce sieci oraz trasowaniu)
                pc.icmp++;
                protocol = "ICMP";
                wyswietlanie_pakietow_icmp(buf, data_size);
                emit capturedPacketData(sourceIP, sourceMAC, destIP, destMAC, protocol, length, getPacketsTxt());               
                break;

            case 2:  //protokol igmp ( komputery wysylaja komunikaty igmp kiedy wysylaja zadanie do rutera sieciowego aby dolaczyc sie lub odejsc z danej grupy
            // multicastowej ( multicast - dzieki czemu unika sie wysylania takiego samego komunikatu do wielu odbiorcow)
                pc.igmp++;
                protocol = "IGMP";
                break;

            case 6:  //protokol tcp ( zapewnia komunikacje miedzy klientem a serwerem ( nie trzeba sie przejmowac utrata danych))
                pc.tcp++;
                protocol = "TCP";
                wyswietlanie_pakietow_tcp(buf, data_size);
                emit capturedPacketData(sourceIP, sourceMAC, destIP, destMAC, protocol, length, getPacketsTxt());

                break;

            case 17: //protokol udp ( nie zapewnia bezstratnej wymiany informacji ale za to jest szybszy niż TCP)
                pc.udp++;
                protocol = "UDP";
                wyswietlanie_pakietow_udp(buf , data_size);
                emit capturedPacketData(sourceIP, sourceMAC, destIP, destMAC, protocol, length, getPacketsTxt());
                break;
	`
            default: //inne protokoly takie jak ARP itp
                pc.etc++;

                break;
        }
        emit capturedPacketsCounts(QString::asprintf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Inne : %d   Lacznie : %d", pc.tcp,pc.udp,pc.icmp,pc.igmp,pc.etc,pc.all));
    }
    close(raw_sock);
    raw_sock = -1;
    emit finished();
}
//------------------------------------------------------------------
void SnifferWorker::stopSniff()
{
    working = false;
}
//------------------------------------------------------------------
QString SnifferWorker::getPacketsTxt()
{
    QString ret;
    for (auto it = packetstxt.constBegin(); it != packetstxt.constEnd(); ++it)
    {
        ret = ret % *it;
    }
    qDebug() << "Length: " << ret.size() << "----------------";
    return ret;
    //return packetstxt.readAll();
}
//------------------------------------------------------------------
void SnifferWorker::wyswietlanie_pakietow_icmp(unsigned char* bufor , int rozmiar)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(bufor + sizeof(struct ethhdr)); //przypisanie wskaznikowi iph naglowka ip adresu pierwszego bajtu w buforze
    iphdrlen = iph->ihl*4; // 4 32 bitowe slowa w headerze

    struct icmphdr *icmph = (struct icmphdr *)(bufor + iphdrlen + sizeof(struct ethhdr)); // przypisanie wskaznikowi icmph adresu bajtu za ostatnim elementem naglowka iph

    int rozmiar_naglowka_icmp =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
    packetstxt<< QString::asprintf("\n\n***********************ICMP Pakiety*************************\n");

    wyswietlanie_ip_naglowkow(bufor , rozmiar);

    packetstxt<< QString::asprintf("\n");

    packetstxt<< QString::asprintf("ICMP Header\n");
    packetstxt<< QString::asprintf("   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
        packetstxt<< QString::asprintf("  (Przekroczony czas )\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) // ICMP_ECHOREPLY - sprawdzenie polaczenia sieciowego( odpowiedz na zadanie ICMP_ECHOREQUEST
        packetstxt<< QString::asprintf("  (ICMP Echo Reply)\n");

    packetstxt<< QString::asprintf("   |-Code : %d\n",(unsigned int)(icmph->code));
    packetstxt<< QString::asprintf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(plik_z_pakietami , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(plik_z_pakietami , "   |-Sequence : %d\n",ntohs(icmph->sequence));


    packetstxt<< QString::asprintf("\n");

    packetstxt<< QString::asprintf("IP Header\n");
    wyswietl_dane(bufor,iphdrlen);

    packetstxt<< QString::asprintf("UDP Header\n");
    wyswietl_dane(bufor + iphdrlen , sizeof icmph);

    packetstxt<< QString::asprintf("Wiadomosc\n");
    wyswietl_dane(bufor + rozmiar_naglowka_icmp, rozmiar - rozmiar_naglowka_icmp);

}
//------------------------------------------------------------------
void SnifferWorker::wyswieltenie_naglowka_ethernet(unsigned char* bufor, int rozmiar)
{
    struct ethhdr *eth = (struct ethhdr *)bufor;

    packetstxt<< QString::asprintf("\n");
    packetstxt<< QString::asprintf("Ethernet Header\n");
    packetstxt<< QString::asprintf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    packetstxt<< QString::asprintf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    packetstxt<< QString::asprintf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
    destMAC = QString::asprintf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    sourceMAC = QString::asprintf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
}
//------------------------------------------------------------------
void SnifferWorker::wyswietlanie_ip_naglowkow(unsigned char* bufor, int rozmiar) // funkcja wyswietlajaca naglowek ip
{

    wyswieltenie_naglowka_ethernet(bufor,rozmiar);

    struct iphdr *iph = (struct iphdr *)(bufor + sizeof(struct ethhdr)); //  przypisanie wskaznikowi iph naglowka ip adresu pierwszego bajtu w buforze
    iphdrlen =iph->ihl*4; // dlugosc pakietow IP w bajtach ( ihl -> dlugosc naglowka IP) ihl - internet header length

    memset(&source, 0, sizeof(source));  // wypelnia kolejne bajty w pamieci ustalona wartoscia ,  &source adres poczatkowy 0 - wpisywana wartosc sizeof(source) - ile bajtow zapisac
    source.sin_addr.s_addr = iph->saddr; // przypisanie adresu IP source

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr; // przypisanie adresu IP destination

    packetstxt<< QString::asprintf("\n");
    packetstxt<< QString::asprintf("IP Header\n");
    packetstxt<< QString::asprintf("   |-IP Version        : %d\n",(unsigned int)iph->version); // wersja protokolu IP
    packetstxt<< QString::asprintf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4); // dword = 4bytes
    packetstxt<< QString::asprintf("   |-IP Total Length   : %d  Bytes(Rozmiar pakietu)\n",ntohs(iph->tot_len));//ntohs konwertuje unsigned short integer z sieciowej kolejnosci bitow na kolejnosc bitow hosta
    packetstxt<< QString::asprintf("   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(plik_z_pakietami , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(plik_z_pakietami , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(plik_z_pakietami , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    packetstxt<< QString::asprintf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    packetstxt<< QString::asprintf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    packetstxt<< QString::asprintf("   |-Checksum : %d\n",ntohs(iph->check));
    packetstxt<< QString::asprintf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr)); // inet_ntoa - funkcja kowertujaca adres sieci
    packetstxt<< QString::asprintf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

    sourceIP = QString::asprintf("%s\n",inet_ntoa(source.sin_addr)); // inet_ntoa - funkcja kowertujaca adres sieci
    destIP = QString::asprintf("%s\n",inet_ntoa(dest.sin_addr));
}
//------------------------------------------------------------------
void SnifferWorker::wyswietl_dane (unsigned char* data , int Size)
{
    int i;
    int j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //jesli jedna linia wyswietlania heksydecymalnego jest zapelniona
        {
            packetstxt<< QString::asprintf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    packetstxt<< QString::asprintf("%c",(unsigned char)data[j]); //jesli to jest numer albo litera alfabetu
                    //%c argument typu int jest konwertowany do unsigned char i wynikowy znak jest wypisywany.

                else packetstxt<< QString::asprintf("."); //w innym przypadku wyswietlaj kropke
            }
            packetstxt<< QString::asprintf("\n");
        }

        if(i%16==0) packetstxt<< QString::asprintf("   ");
            packetstxt<< QString::asprintf(" %02X",(unsigned int)data[i]); // %02X wyswietlaj przynajmniej dwie liczby int

        if( i==Size-1)  // wyswietlaj ostatni znak jako spacje
        {
            for(j=0;j<15-i%16;j++) packetstxt<< QString::asprintf("   "); //dodatkowe spacje

            packetstxt<< QString::asprintf("         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) packetstxt<< QString::asprintf("%c",(unsigned char)data[j]);
                else packetstxt<< QString::asprintf(".");
            }
            packetstxt<< QString::asprintf("\n");
        }
    }
}
//------------------------------------------------------------------
void SnifferWorker::wyswietlanie_pakietow_tcp(unsigned char* bufor, int rozmiar)
{
    unsigned short iphdrlen; // zmienna do ktorej przypisywana jest dlugosc pakietow IP

    struct iphdr *iph = (struct iphdr *)(bufor + sizeof(struct ethhdr)); //przypisanie wskaznikowi iph naglowka ip adresu pierwszego bajtu w buforze
    iphdrlen = iph->ihl*4;//dlugosc pakietow IP w bajtach ( ihl -> dlugosc naglowka IP) ihl - internet header length

    struct tcphdr *tcph=(struct tcphdr*)(bufor + iphdrlen + sizeof(struct ethhdr)); // przypisanie wskaznikowi tcph adresu bajtu za ostatnim elementem naglowka iph


    int rozmiar_naglowka_tcp =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    packetstxt<< QString::asprintf("\n\n***********************TCP Pakiety*************************\n");

    wyswietlanie_ip_naglowkow(bufor,rozmiar);

    packetstxt<< QString::asprintf("\n");
    packetstxt<< QString::asprintf("TCP Header\n");
    packetstxt<< QString::asprintf("   |-Source Port      : %u\n",ntohs(tcph->source));
    packetstxt<< QString::asprintf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    packetstxt<< QString::asprintf( "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    packetstxt<< QString::asprintf( "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    packetstxt<< QString::asprintf( "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(plik_z_pakietami , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(plik_z_pakietami , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    packetstxt<< QString::asprintf( "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    packetstxt<< QString::asprintf( "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    packetstxt<< QString::asprintf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    packetstxt<< QString::asprintf( "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    packetstxt<< QString::asprintf( "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    packetstxt<< QString::asprintf( "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    packetstxt<< QString::asprintf( "   |-Window         : %d\n",ntohs(tcph->window));
    packetstxt<< QString::asprintf( "   |-Checksum       : %d\n",ntohs(tcph->check));
    packetstxt<< QString::asprintf( "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    packetstxt<< QString::asprintf("\n");
    packetstxt<< QString::asprintf("                        DANE                        ");
    packetstxt<< QString::asprintf("\n");

    packetstxt<< QString::asprintf("IP Header\n");
    wyswietl_dane(bufor,iphdrlen);

    packetstxt<< QString::asprintf("TCP Header\n");
    wyswietl_dane(bufor+iphdrlen,tcph->doff*4); // tcp->doff*4 -> wskaznik na koncowy element protokolu TCP

    packetstxt<< QString::asprintf("Wiadomosc\n");
    wyswietl_dane(bufor + rozmiar_naglowka_tcp,rozmiar - rozmiar_naglowka_tcp );

    length = QString::asprintf( "%d \n" ,rozmiar);


}
//------------------------------------------------------------------
void SnifferWorker::wyswietlanie_pakietow_udp(unsigned char *bufor , int rozmiar)
{

    unsigned short iphdrlen; // zmienna do ktorej przypisywana jest dlugosc pakietow IP

    struct iphdr *iph = (struct iphdr *)(bufor + sizeof(struct ethhdr)); //przypisanie wskaznikowi iph naglowka ip adresu pierwszego bajtu w buforze
    iphdrlen = iph->ihl*4; // dlugosc pakietow IP w bajtach ( ihl -> dlugosc naglowka IP) ihl - internet header length

    struct udphdr *udph = (struct udphdr*)(bufor + iphdrlen + sizeof(struct ethhdr)); // przypisanie wskaznikowi udph adresu bajtu za ostatnim elementem naglowka iph

    int rozmiar_naglowka_udp =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

   packetstxt<< QString::asprintf("\n\n***********************UDP Pakiety*************************\n");

    wyswietlanie_ip_naglowkow(bufor,rozmiar);

    packetstxt<< QString::asprintf("\nUDP Header\n");
    packetstxt<< QString::asprintf("   |-Source Port      : %d\n" , ntohs(udph->source));
    packetstxt<< QString::asprintf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    packetstxt<< QString::asprintf("   |-UDP Length       : %d\n" , ntohs(udph->len));// ntohs(konwertuje wartosc unsigned short z kolejnosci bitowej sieciowej na kolejnosc bitowa hosta
    packetstxt<< QString::asprintf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));


     packetstxt<< QString::asprintf("\n");
     packetstxt<< QString::asprintf("IP Header\n");
    wyswietl_dane(bufor , iphdrlen);

     packetstxt<< QString::asprintf("UDP Header\n");
    wyswietl_dane(bufor+iphdrlen , sizeof udph);

     packetstxt<< QString::asprintf("Wiadomosc\n");
    wyswietl_dane(bufor + rozmiar_naglowka_udp , rozmiar - rozmiar_naglowka_udp);


}


//------------------------------------------------------------------
