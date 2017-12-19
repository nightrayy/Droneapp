#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QProcess> // klasa do polecen systemoych
#include <QRegExp> // klasa do rozdzielenia danych z pliku tekstowego

#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    x(101), y(101) // 101 punktow na osi X i Y
{
    ui->setupUi(this);

    findTimer = new QTimer(); // stworzenie tego timera
    findTimer->setInterval(2000); // ustawienie czasu odswiezania interwalowego w ms
    connect(findTimer,&QTimer::timeout,this,&MainWindow::findActiveWirelesses); // funkcja laczaca timer z funkcja znajdujaca aktywne polaczenia sieciowe
    //findTimer->start();
    foundCount = 0; // wyzerowanie licznika dostepnych polaczen
    ui->treeWidgetWiFis->setColumnWidth(0,50); // ustawienie rozmiaru kolumny
    ui->treeWidgetWiFis->setColumnWidth(1,200);


    //findActiveWirelesses();
    connect(&connProc, SIGNAL(finished(int)), this, SLOT(connectingFinished(int)));
    // polaczenie procesu polaczenia sie z dana siecia z funkcja konczaca polaczenie
    //connect(&sw, SIGNAL(capturedPacket(QString)), this, SLOT(test(QString)));

    ui->plot->xAxis->setRange(-1.4, 15.4); // ustawienie skali w osi x przy rysowaniu
    ui->plot->yAxis->setRange(0, 105); // ustawienie skali w osi y przy rysowaniu
    ui->plot->xAxis->setLabel("Channel"); // ustawienie opisu osi X
    ui->plot->yAxis->setLabel("Signal strength [%]"); // ustawienie opisu osi Y

    QSharedPointer<QCPAxisTickerText> textTicker(new QCPAxisTickerText);
    ui->plot->xAxis->setTicker(textTicker);

    for (int i = 1; i < 14; i++)
        textTicker->addTick((double)i, QString::number(i)); // zaznaczenie poszczegolnych cyfr na wykresie oznaczajacych numery kanalu sieci Wi-Fi

    colorPens = {
        QPen(QColor(255, 0, 0)), // czerwony
        QPen(QColor(0, 255, 0)), // zielen jaskrawa
        QPen(QColor(0, 0, 255)), // niebieski
        QPen(QColor(255, 0, 255)), // magenta
        QPen(QColor(128, 0, 128)) // jagodowy
    };
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::findActiveWirelesses()
{
    findTimer->blockSignals(true); // na czas znajdowania aktywnych polaczen blokuj sygnal od timera
    system("nmcli device wifi rescan"); // polecenie systemowe wykorzystywane do ponownego skanowania sieci.
    QProcess p;
    p.start("nmcli -f ssid,bssid,chan,freq,signal,security dev wifi list"); // wywolanie polecenia systemowego do skanowania wyswietlajace ssid i adres MAC
//    p.start("sudo airodump-ng wlan0"); // wywolanie polecenia systemowego do skanowania wyswietlajace ssid i adres MAC
    p.waitForFinished(-1); // zakonczenie blokowania sygnalu

    QString outStr = QString(p.readAllStandardOutput().data()); // funkcja zapisujaca do outStr wszystkie pobrane dane
    QStringList rawAPs = outStr.split(QRegExp("[\r\n]"), QString::SkipEmptyParts); // funkcja rozdzielajaca pobrane dane z pominieciem spacji
//    qDebug() << rawAPs;
    QStringList aps;
    //QRegExp rx("(.+[^ ]+)\\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\\s+([0-9]{1,2}})\\s+([0-9]{4}) MHz\\s+([0-9]{1,3}})"); // obiekt wyrazenia regularnego sprawdzajacy gdzie znajduje sie ades MAC
    QRegExp rx("(.+[^ ]+)\\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\\s+([0-9]{1,2})\\s+([0-9]{4}) MHz\\s+([0-9]{1,3})\\s+((\\S+\\s?)+)\\s");
    /*
     * . - wszystkie znaki
     * ^ - od poczatku stringa
     * s - laczy znaki ze spacja
     * S - laczy znaki bez spacji
     * ? - poprzednie wyrazenie jest opcjonalne
     * \\ kolejne wyrazenie
     * + laczy jedno lub wiecej wystapienia poprzedniego znaku
        1. całość
        2. ESSID
        3. MAC
        4. ---
        5. ---
        6. channel
        7. freq
        8. signal
        9. security
    */



    QTreeWidgetItem *prevItem = ui->treeWidgetWiFis->currentItem(); // pobranie akualnego obiektu i przypisanie do wskaznika
    QString mac = ""; // ustawienie pustego miejsca na adres MAC
    if (prevItem != nullptr) {
        mac = prevItem->text(2); // wpisanie do tabeli wartosci adresow mac
        //qDebug() << mac;
    }

    // przed rysowaniem wyczysc okno, graf
    ui->treeWidgetWiFis->clear(); // wyczyszczenie okna
    ui->plot->clearGraphs();
    ui->plot->clearItems();

    int net_count = 0; // licznik znalezionych sieci
    prevItem = nullptr;
    for (QString &ap : rawAPs) {
        //qDebug() << ap;
        if (rx.indexIn(ap)  >= 0) {
            QStringList data = rx.capturedTexts();
            //qDebug() << data;
            QTreeWidgetItem * item = new QTreeWidgetItem();
            item->setText(0, QString::number(net_count+1)); // kolumna z numerem polaczenia
            item->setText(1, data[1]); // kolumna z wartoscia ssid
            item->setText(2, data[2]); // kolumna z adresem mac
            item->setText(3, data[8]); // kolumna z zabezpieczeniem
            item->setText(4, data[5]); // kolumna z numerem kanalu
            item->setText(5, data[6]); // kolumna z czestotliwoscia[GHz]
            item->setText(6, data[7]); // kolumna z moca sygnalu [%]

            ui->treeWidgetWiFis->addTopLevelItem(item);
            if (data[2] == mac) {
                prevItem = item;
            }
            //Sprawdzamy, czy to jest adres MAC drona i jesli tak to kolorujemy wszystkie kolumny
            if (macs.contains(data[2].mid(0, 8))) {
                QColor color(128, 0, 0); // funkcja kolorujaca polaczenia od drona ( bordowy)
                item->setBackgroundColor(0, color);
                item->setBackgroundColor(1, color);
                item->setBackgroundColor(2, color);
                item->setBackgroundColor(3, color);
                item->setBackgroundColor(4, color);
                item->setBackgroundColor(5, color);
                item->setBackgroundColor(6, color);
            }



            // Sprawdzamy czy mamy wystarczająca liczbe wykresów
//            if (ui->plot->graphCount() < net_count) {
            ui->plot->addGraph();
//            }

            // generujemy parabolę
            QPen &pen = colorPens[net_count%colorPens.count()];
            genParabole(data[5].toInt(), data[7].toInt()); // funkcja generujaca parabole
            ui->plot->graph(net_count)->setData(x, y);
            ui->plot->graph(net_count)->setPen(pen);

            QCPItemText *text = new QCPItemText(ui->plot);
            text->setPositionAlignment(Qt::AlignHCenter);
            text->setFont(QFont(font().family(), 8));
            text->position->setType(QCPItemPosition::ptPlotCoords);
            text->position->setCoords(x[50], y[50]+2.0);
            text->setText(data[1]);
            text->setColor(pen.color());

            net_count++;
        }

    }

    if (prevItem != nullptr) {
        ui->treeWidgetWiFis->setCurrentItem(prevItem);
    }

    // Generowanie wykresu
//    for (int i = ui->plot->graphCount(); i < 2; i++) {
//        ui->plot->addGraph();
//    }
//    genParabole(3, 70);
//    ui->plot->graph(0)->setData(x, y);
//    genParabole(4, 40);
//    ui->plot->graph(1)->setData(x, y);

    ui->plot->replot();

    findTimer->blockSignals(false); // zakonczenie blokowania sygnalow

}

void MainWindow::connectingFinished(int exitCode)
{
    qDebug() << "connect: " << exitCode; // sprawdzenie wartosci connect czy nastapilo prawidlowe rozlaczenie
    connWnd.hide(); // ukrycie okna na czas zakonczenie polaczenia
    if (exitCode == 0) { // jesli zakonczenie polaczenia sie udalo

    } else { // jesli nastapil jakis blad
        QMessageBox::warning(nullptr, "Connection", "Can't connect with SSID: " + connWnd.getSSID() + " BSSID: " + connWnd.getBSSID());
    }
    show(); // jesli wszystko jest w porzadku pokaz okno
    findTimer->start();// uruchomienie timera na aktualizacje polaczen co 2 sekundy
}

void MainWindow::on_pushButton_clicked() // po nacisnieciu przycisku skanuj
{
    findActiveWirelesses(); // wywolanie funkcji znajdujacej aktynwe polaczenia sieciowe
    findTimer->start(); // uruchomienie timera na aktualizacje polaczen co 2 sekundy
    //sw.start(); // rozpoczecie watku od sniffera pakietow
//    snifferWnd.show();
//    snifferWnd.startSniffing();
}

void MainWindow::on_pushButton_2_clicked() // po nacisnieciu przycisku polacz
{
    QTreeWidgetItem *item = ui->treeWidgetWiFis->currentItem(); // zwraca aktualna pozycje w treeWidgecie
    if (item == nullptr || !macs.contains(item->text(2).mid(0, 8))) { // sprawdzenie czy wybieramy odpowiednia siec od drona
        QMessageBox::warning(nullptr, "Connection", "Please choose correct network!");
        return;
    }
    hide(); // ukrycie okna podstawowego na czas polaczenia sie z dana siecia

    connWnd.setParams(item->text(1), item->text(2));
    connWnd.show();
    findTimer->stop();
    connProc.start((QString("nmcli d wifi connect ") + item->text(2)).toLatin1().data());
}

void MainWindow::on_pushButton_3_clicked()
{
    hide();
    snifferWnd.show();
    snifferWnd.startSniffing();
    snifferWnd.parentWnd = this;
    //findTimer->stop();
//    snifferwrk.doSniff();
}


//void MainWindow::test(QString data)
//{
 //   ui->pushButton_2->setText(data);
//}




void MainWindow::genParabole(int channel, int signal) {
    double w = 2.1;
    double a = -signal/w/w;
    double xl = channel - w;
    double xp = channel + w;
    for (int i = 0; i < 101; i++) {
        x[i] = (xp-xl)/100 * i + xl;
        y[i] = a*(x[i]-xp)*(x[i]-xl);
    }
}

