#ifndef SNIFFERWND_H
#define SNIFFERWND_H

//------------------------------------------------------------------

#include <QWidget>
#include <QThread>

#include "snifferworker.h"


//------------------------------------------------------------------
namespace Ui {
class SnifferWnd;
}

class SnifferWnd : public QWidget
{
    Q_OBJECT

public:
    explicit SnifferWnd(QWidget *parent = 0);
    ~SnifferWnd();

    void startSniffing();
    void stopSniffing();
    QWidget *parentWnd;

public slots:
    void snifferFinished();
    void snifferData(QString data);
    void snifferPacketData(QString sourceIP, QString sourceMAC, QString destIP, QString destMAC, QString protocol, QString length, QString details);
    void snifferError(QString data);

protected:
    void hideEvent(QHideEvent *event);
private slots:
    void on_pushButton_clicked();

    void on_treeWidget_doubleClicked(const QModelIndex &index);

private:
    Ui::SnifferWnd *ui;
    SnifferWorker sw;
    QThread swThread;
    int packet_counter = 0;

    void closeEvent (QCloseEvent *event);
};

//------------------------------------------------------------------

#endif // SNIFFERWND_H
