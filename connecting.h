// klasa sluzaca do tego aby polaczyc sie z dana siecia Wi-Fi
// pobiera i ustawia parametry sieciowe  takie jak ssid,adres MAC
// Jest odpowiedzialna za polaczenie sie z odpowiednia siecia rozglaszana przez drona

#ifndef CONNECTING_H
#define CONNECTING_H

#include <QWidget>

//------------------------------------------------------------------
namespace Ui {
class Connecting;
}

//------------------------------------------------------------------
class Connecting : public QWidget
{
    Q_OBJECT

public:
    explicit Connecting(QWidget *parent = 0);
    ~Connecting();

    void setParams(QString ssid, QString bssid); // funkcja ustawiajaca parametry takie jak ssid czy adres mac
    QString getSSID(); // funkcja sluzaca do pobrania wartosci SSID
    QString getBSSID(); // funkcja sluzaca do pobrania adresu MAC

private:
    Ui::Connecting *ui; // wskaznik na obiekt sluzacy do umiejscowienia wartosci w tabeli
};

#endif // CONNECTING_H
