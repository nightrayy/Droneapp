#include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QRegExp>

#include <fstream>
#include <string>

#include <unistd.h>
#include <errno.h>

using namespace std;

int main(int argc, char *argv[])
{
    int euid = geteuid();
    if (euid != 0) {
        execl("/usr/bin/gksu", "/usr/bin/gksu", "-kS", argv[0], (char*)nullptr); // uruchomienie programu z prawami administratora
        return -1;
   }
    QApplication a(argc, argv);
    MainWindow w;

    //Wczytujemy adresy mac z pliku ADRESY_MAC.txt
    ifstream fileMACs((QCoreApplication::applicationDirPath() + "/ADRESY_MAC.txt").toStdString());
    if (!fileMACs.is_open()) {
        QMessageBox::critical(nullptr, "Error during application starting", "Can't read mac addresses from file ADRESY_MAC.txt");
        return -1;
    }
    //Wczytujemy adresy mac
    QSet<QString> macs; // wektor wartosci QString na adresy MAC
    QRegExp rx("[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}");
    string line;
    do {
        getline(fileMACs, line); // pobieranie kazdej linijki pliku tekstowego
        if (line.length() == 0) // sprawdzenie aż do momentu konca pliku
            break;
        //Parsowanie adresu mac
        if (rx.indexIn(QString::fromStdString(line))  >= 0) { // zwraca pozycje pierszego pasujacej linii tekstu
            QStringList data = rx.capturedTexts();
            macs.insert(data[0]);
        } else {
            QMessageBox::critical(nullptr, "Error during application starting", "Incorrect file format in ADRESY_MAC.txt");
            fileMACs.close(); // zamkniecie pliku z adresami MAC i nazwami firm dronow
            return -2;
        }

    } while (true);
    fileMACs.close();// zamkniecie pliku z adresami MAC i nazwami firm dronow

    w.setMacs(macs); // ustawienie wartosci adresow MAC w tabeli
    w.show(); // pokazanie glownego okna programu
    qDebug() << "Application started";

    return a.exec();
}
