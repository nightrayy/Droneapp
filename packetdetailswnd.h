#ifndef PACKETDETAILSWND_H
#define PACKETDETAILSWND_H

#include <QDialog>

namespace Ui {
class PacketDetailsWnd;
}

class PacketDetailsWnd : public QDialog
{
    Q_OBJECT

public:
    explicit PacketDetailsWnd(QDialog *parent = 0);
    ~PacketDetailsWnd();
    void setText(QString &txt);

private:
    Ui::PacketDetailsWnd *ui;
};

#endif // PACKETDETAILSWND_H
