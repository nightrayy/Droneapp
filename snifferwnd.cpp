#include "snifferwnd.h"
#include "ui_snifferwnd.h"
#include "packetdetailswnd.h"

#include <QDebug>
#include <QMessageBox>
#include <QHeaderView>

SnifferWnd::SnifferWnd(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SnifferWnd)
{
    ui->setupUi(this);
    sw.moveToThread(&swThread);
    //swThread.setObjectName("testowy");
    connect(&swThread, SIGNAL(started()), &sw, SLOT(doSniff()));
    connect(&sw, SIGNAL(finished()), &swThread, SLOT(quit()));
    connect(&sw, SIGNAL(finished()), this, SLOT(snifferFinished()));
    connect(&sw, SIGNAL(capturedPacketsCounts(QString)), this, SLOT(snifferData(QString)));
    connect(&sw, SIGNAL(capturedPacketData(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(snifferPacketData(QString,QString,QString,QString,QString,QString,QString)));
    connect(&sw, SIGNAL(snifferError(QString)), this, SLOT(snifferError(QString)));
    //ui->treeWidget->header()->setResizeMode(Stretch);
}

SnifferWnd::~SnifferWnd()
{
    delete ui;
}

void SnifferWnd::startSniffing()
{
    packet_counter = 0;
    ui->treeWidget->clear();
    ui->label->setText("- - - - -");
    swThread.start();
    //ui->plainTextEdit->hide();
    //ui->plainTextEdit->resize(ui->plainTextEdit->width(), 0);
//    ui->horizontalLayout->update();
}

void SnifferWnd::stopSniffing()
{
    sw.stopSniff();
}

void SnifferWnd::snifferFinished()
{
    //ui->plainTextEdit->show();
    //ui->plainTextEdit->resize(ui->plainTextEdit->width(), 400);
//    ui->plainTextEdit->clear();
//    QString txt = sw.getPacketsTxt();
//    ui->plainTextEdit->appendPlainText(txt);
}

void SnifferWnd::snifferData(QString data)
{
    //QString desc = QString::asprintf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Inne : %d   Lacznie : %d", pc.tcp,pc.udp,pc.icmp,pc.igmp,pc.etc,pc.all);
    ui->label->setText(data);
}

void SnifferWnd::snifferPacketData(QString sourceIP, QString sourceMAC, QString destIP, QString destMAC, QString protocol, QString length, QString details)
{
    QTreeWidgetItem * item = new QTreeWidgetItem();
    item->setText(0, QString::number(++packet_counter)); // kolumna z numerem pakietu
    item->setText(1, sourceIP); // kolumna z wartoscia ssid
    item->setText(2, sourceMAC); // kolumna z adresem mac
    item->setText(3, destIP); // kolumna z zabezpieczeniem
    item->setText(4, destMAC); // kolumna z numerem kanalu
    item->setText(5, protocol); // kolumna z czestotliwoscia[GHz]
    item->setText(6, length); // kolumna z moca sygnalu [%]
    QVariant v;
    v.setValue(details);
    item->setData(0, Qt::UserRole, v);
    //qDebug() << "haha";


    ui->treeWidget->addTopLevelItem(item);
}

void SnifferWnd::snifferError(QString data)
{
    QMessageBox::critical(nullptr, "Error during sniffing", data);
}

void SnifferWnd::hideEvent(QHideEvent *event)
{
    //sw.stopSniff();
}

void SnifferWnd::on_pushButton_clicked()
{
    stopSniffing();
}

void SnifferWnd::on_treeWidget_doubleClicked(const QModelIndex &index)
{
    QVariant v = ui->treeWidget->currentItem()->data(0, Qt::UserRole);
    QString s = v.value<QString>();
    //QMessageBox::information(nullptr, "Packet details", s);
    PacketDetailsWnd pdWnd;
    pdWnd.setText(s);
    pdWnd.exec();
}

void SnifferWnd::closeEvent(QCloseEvent *event)
{
    stopSniffing();
    swThread.exit();
    parentWnd->show();
}
