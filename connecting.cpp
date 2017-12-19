#include "connecting.h" // plik naglowkowy klasy sluzacej do polaczenia sie z dana siecia
#include "ui_connecting.h" // plik tworzony automatycznie przez QT po zbudowaniu

Connecting::Connecting(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Connecting)
{
    ui->setupUi(this); // wstepne ustawienie obiektu ui
}

Connecting::~Connecting()
{
    delete ui; // dealokacja pamieci
}

void Connecting::setParams(QString ssid, QString bssid) // funkcja ustawiajaca parametry
{
    ui->labelSSID->setText(ssid); // ustawienie w polu labelSSID wartosci ssid
    ui->labelBSSID->setText(bssid); // ustawienie w polu labelBSSID wartosci BSSID(adres MAC)
}

QString Connecting::getSSID()
{
    return ui->labelSSID->text(); // pobranie wartosci SSID z pola labelSSID
}

QString Connecting::getBSSID()
{
    return ui->labelBSSID->text(); // pobranie wartosci adresu MAC z pola labelBSSID
}
