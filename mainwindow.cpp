#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QRandomGenerator>
#include <QString>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Generate a 256-bit key (32 bytes)
    m_currentKey.resize(32);
    for (int i = 0; i < 32; ++i) {
        m_currentKey[i] = static_cast<uint8_t>(QRandomGenerator::global()->bounded(256));
    }

    // Initialize encryption with this key
    m_crypto.setKey(m_currentKey);

    // Connect signals to slots
    connect(ui->pushButton, &QPushButton::clicked,
            this, &MainWindow::onEncryptButtonClicked);
    connect(ui->pushButton_2, &QPushButton::clicked,
            this, &MainWindow::onDecryptButtonClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onEncryptButtonClicked()
{
    // 1. Get plaintext from UI
    QString plaintext = ui->lineEdit->text();

    // 2. Convert to bytes and encrypt
    std::vector<uint8_t> plaintextBytes = AdvancedEncryption::stringToBytes(plaintext.toStdString());
    std::vector<uint8_t> ciphertextBytes = m_crypto.encrypt(plaintextBytes);

    // 3. Convert to hex and display
    QString hexCiphertext = QString::fromStdString(AdvancedEncryption::bytesToHex(ciphertextBytes));
    ui->lineEdit_2->setText(hexCiphertext);
}

void MainWindow::onDecryptButtonClicked()
{
    // 1. Get hex-encoded ciphertext from UI
    QString hexCiphertext = ui->lineEdit_3->text();

    // 2. Convert from hex to bytes and decrypt
    try {
        std::vector<uint8_t> ciphertextBytes = AdvancedEncryption::hexToBytes(hexCiphertext.toStdString());
        std::vector<uint8_t> decryptedBytes = m_crypto.decrypt(ciphertextBytes);

        // 3. Convert decrypted bytes to string and display
        QString decryptedPlaintext = QString::fromStdString(AdvancedEncryption::bytesToString(decryptedBytes));
        ui->lineEdit_4->setText(decryptedPlaintext);
    } catch (const std::exception &e) {
        // Show error in UI
        ui->lineEdit_3->setText(QString("Error: %1").arg(e.what()));
    }
}
