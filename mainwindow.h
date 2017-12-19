#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer> // naglowek do wprowadzenia timera do odswiezania polecenia systemowego
#include <QList> //  naglowek do przechowywania obiektow w postaci listy
#include <QSet> // naglowek do przechowywania pobieranych wartosci
#include <QProcess> // naglowek do polecenia systemowego
#include <QInputDialog> // naglowek do wpisywaniw wartosci przez uzytkownika
#include <QStandardItem> // naglowek umozliwiajacy obiektom uzycie ich z klasa QStandardItemModel
#include <QStandardItemModel> // naglowek do stworzenia ogolnego modelu na przechowywanie danych
#include <QNetworkConfiguration> // naglowek sluzacy do konfiguracji access-pointow
#include <QNetworkConfigurationManager> // naglowek umozliwiajacy dostep do konfiguracji sieciowej dla systemu
#include <QNetworkSession> // umozliwia kontrole nad access pointami i umozliwia ich zarzadzanie gdy duzo klientow podlaczy sie pod jedna siec.

#include "connecting.h"
#include "snifferwnd.h"
#include "snifferworker.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    int foundCount; // zmienna przechowujaca ilosc znalezionych polaczen
    QNetworkConfiguration netcfg;
    QStringList WiFisList; // Lista danych typu QString na dane
    QList<QNetworkConfiguration> netcfgList; // wektor wartosci QNetworkConfiguration umozliwiajacy konfiguracje access pointow
    void setMacs(QSet<QString> &macs) {
        this->macs = macs; // ustawienie wartosci adresu mac
    }

public slots:
    void findActiveWirelesses(); // funkcja wyszukajaca aktywne polaczenia sieciowe w zasiegu karty sieciowej
    void connectingFinished(int exitCode); // funkcja obslugujaca sytuacje gdy nastapilo zerwanie polaczenia


private slots:
    void on_pushButton_clicked(); // funkcja obslugujaca przycisk skanuj

    void on_pushButton_2_clicked(); // obsluga przyciksu polacz
   // void test(QString data); // przycisk na socket

    void on_pushButton_3_clicked();

private:
    Ui::MainWindow *ui; // wskaznik na glowne okno
    QTimer *findTimer; // wskaznik na timer
    QStandardItemModel* listModel; // wskaznik na klase w ktorej umieszczone beda dane
    QNetworkSession *session; // wskaznik na access pointy z ktorych wydobywane beda informacje
    QSet<QString> macs; // wektor wartosci QString ktore beda ustawiane
    QProcess connProc; // proces do wywolania polecenia systemowego
    Connecting connWnd; // obiekt klasy sluzacej do polaczenia sie z dana siecia
    SnifferWnd snifferWnd; // obiekt klasy sluzacej do pojawienia sie okna sniffera pakietow
//    SnifferWorker snifferwrk; // obiekt klasy sluzacej do pracy sniffera pakietow
    QVector<double> x, y; // wektory wartosci typu double na wspolrzedne
    QVector<QPen> colorPens;

    void genParabole(int channel, int signal); // funkcja generujaca parabole przyjmujaca za argumenty signal i channel
};

#endif // MAINWINDOW_H
