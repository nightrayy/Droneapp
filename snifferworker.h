#ifndef SNIFFERWORKER_H
#define SNIFFERWORKER_H

//------------------------------------------------------------------

#include <QThread> // biblioteka do watkow
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

#include <QStringBuilder>
#include <QStringList>
#include <QTextStream>
#include <QFile>

//------------------------------------------------------------------
struct PacketsCounts {
    unsigned int icmp, igmp, tcp, udp, etc, all;
};
//------------------------------------------------------------------
class SnifferWorker : public QObject
{
    Q_OBJECT
public:
    SnifferWorker();
    ~SnifferWorker();
    QString getPacketsTxt();
public slots:
    void doSniff(); // slot do startu przechwytywania pakietow
    void stopSniff(); // funkcja do zatrzymania przechwytywania pakietów
signals:
    void capturedPacketsCounts(QString data); // sygnał emitowany gdy mamy jakieś informacje o pakiecie (interesującym)
    void capturedPacketData(QString sourceIP, QString sourceMAC, QString destIP, QString destMAC, QString protocol, QString length, QString details);
    void snifferError(QString data); // sygnal emitowany gdy nastapi jakis blad
    void finished();// sygnal do zakoczenia zbierania pakietow
private:
    int raw_sock = -1;
    bool working = false;
    unsigned char *buf = nullptr;
    PacketsCounts pc;
    QStringList packetstxt;

    void wyswietlanie_pakietow_icmp(unsigned char* bufor , int rozmiar);
    void wyswieltenie_naglowka_ethernet(unsigned char* bufor, int rozmiar);
    void wyswietlanie_ip_naglowkow(unsigned char* bufor, int rozmiar);
    void wyswietl_dane (unsigned char* data , int Size);
    void wyswietlanie_pakietow_tcp(unsigned char* bufor, int rozmiar);
    void wyswietlanie_pakietow_udp(unsigned char* bufor, int rozmiar);
    unsigned short iphdrlen; // zmienna do ktorej przypisywana jest dlugosc pakietow IP
    struct sockaddr_in source,dest; // struktura uzywana przez funkcje interfejsu gniazd(socket)
    QString sourceIP, sourceMAC, destIP, destMAC, protocol, length;
};


//------------------------------------------------------------------

#endif // SNIFFERWORKER_H
