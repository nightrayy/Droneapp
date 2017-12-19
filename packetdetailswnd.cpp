#include "packetdetailswnd.h"
#include "ui_packetdetailswnd.h"

PacketDetailsWnd::PacketDetailsWnd(QDialog *parent) :
    QDialog(parent),
    ui(new Ui::PacketDetailsWnd)
{
    ui->setupUi(this);
}

PacketDetailsWnd::~PacketDetailsWnd()
{
    delete ui;
}

void PacketDetailsWnd::setText(QString &txt)
{
    ui->plainTextEdit->insertPlainText(txt);
    ui->plainTextEdit->moveCursor(QTextCursor::Start);
}
