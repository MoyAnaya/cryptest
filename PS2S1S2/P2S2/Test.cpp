// ============================================================
// test.cpp - Programa criptografico completo
// P2S2 - Seguridad en Sistemas Informaticos
// Universidad Miguel Hernandez de Elche
// ============================================================

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "des.h"
#include "aes.h"
#include "gcm.h"
#include "rsa.h"
#include "osrng.h"
#include "base64.h"
#include "files.h"
#include "filters.h"
#include "modes.h"
#include "hex.h"
#include "sha.h"
#include "default.h"
#include "secblock.h"
#include "oaep.h"
#include "pkcspad.h"
#include "pssr.h"
#include "randpool.h"

#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

using namespace CryptoPP;
using namespace std;

// ============================================================
// UTILIDADES
// ============================================================

// Obtener fecha y hora actual en formato "YYYY/MM/DD_HH:MM:SS"
string getFechaHora()
{
    time_t now = time(nullptr);
    tm t;
    localtime_s(&t, &now);
    ostringstream oss;
    oss << put_time(&t, "%Y/%m/%d_%H:%M:%S");
    return oss.str();
}

// Derivar clave (24 bytes) e IV (8 bytes) desde passphrase usando SHA256
void derivarClaveIV(const string& passphrase,
    SecByteBlock& key, SecByteBlock& iv)
{
    SHA256 hash;
    SecByteBlock digest(SHA256::DIGESTSIZE); // 32 bytes
    hash.CalculateDigest(digest,
        (const byte*)passphrase.data(), passphrase.size());

    key.Assign(digest, DES_EDE3::DEFAULT_KEYLENGTH); // primeros 24 bytes
    iv.Assign(digest + DES_EDE3::DEFAULT_KEYLENGTH,
        DES_EDE3::BLOCKSIZE);                        // siguientes 8 bytes
}

// ============================================================
// MODULO 1: CIFRADO SIMETRICO DES-EDE CBC
// ============================================================

string cifrarDESEDE(const string& texto, const string& passphrase)
{
    SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
    SecByteBlock iv(DES_EDE3::BLOCKSIZE);
    derivarClaveIV(passphrase, key, iv);

    string cifrado;
    CBC_Mode<DES_EDE3>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    StringSource(texto, true,
        new StreamTransformationFilter(enc,
            new Base64Encoder(new StringSink(cifrado))
        )
    );
    return cifrado;
}

string descifrarDESEDE(const string& cifradoB64, const string& passphrase)
{
    SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
    SecByteBlock iv(DES_EDE3::BLOCKSIZE);
    derivarClaveIV(passphrase, key, iv);

    string claro;
    CBC_Mode<DES_EDE3>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    StringSource(cifradoB64, true,
        new Base64Decoder(
            new StreamTransformationFilter(dec, new StringSink(claro))
        )
    );
    return claro;
}

// ============================================================
// MODULO 2: CIFRADO SIMETRICO AES-GCM
// ============================================================

void cifrarAESGCM(const string& texto,
    string& claveHex, string& ivHex, string& cifradoB64)
{
    AutoSeededRandomPool rng;

    // Generar clave aleatoria AES-256 (32 bytes)
    SecByteBlock key(AES::MAX_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    // Generar IV aleatorio (12 bytes, estandar para GCM)
    SecByteBlock iv(12);
    rng.GenerateBlock(iv, iv.size());

    // Guardar clave e IV en hexadecimal
    StringSource(key, key.size(), true,
        new HexEncoder(new StringSink(claveHex)));
    StringSource(iv, iv.size(), true,
        new HexEncoder(new StringSink(ivHex)));

    // Cifrar con AES-GCM
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    StringSource(texto, true,
        new AuthenticatedEncryptionFilter(enc,
            new Base64Encoder(new StringSink(cifradoB64))
        )
    );
}

string descifrarAESGCM(const string& cifradoB64,
    const string& claveHex, const string& ivHex)
{
    string keyStr, ivStr;
    StringSource(claveHex, true, new HexDecoder(new StringSink(keyStr)));
    StringSource(ivHex, true, new HexDecoder(new StringSink(ivStr)));

    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());

    string claro;
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());
    StringSource(cifradoB64, true,
        new Base64Decoder(
            new AuthenticatedDecryptionFilter(dec, new StringSink(claro))
        )
    );
    return claro;
}

// ============================================================
// MODULO 3: RSA - Generacion, cifrado y descifrado
// ============================================================

RSA::PrivateKey g_privateKey;
RSA::PublicKey  g_publicKey;
bool g_tengoClaves = false;

void generarParClaves()
{
    AutoSeededRandomPool rng;
    g_privateKey.GenerateRandomWithKeySize(rng, 2048);
    g_publicKey = RSA::PublicKey(g_privateKey);
    g_tengoClaves = true;
    cout << "\nOK: Par de claves RSA de 2048 bits generado correctamente." << endl;
}

string cifrarRSAPublico(const string& texto)
{
    AutoSeededRandomPool rng;
    string cifrado;
    RSAES_OAEP_SHA_Encryptor enc(g_publicKey);
    StringSource(texto, true,
        new PK_EncryptorFilter(rng, enc,
            new Base64Encoder(new StringSink(cifrado))
        )
    );
    return cifrado;
}

string descifrarRSAPrivado(const string& cifradoB64)
{
    AutoSeededRandomPool rng;
    string claro;
    RSAES_OAEP_SHA_Decryptor dec(g_privateKey);
    StringSource(cifradoB64, true,
        new Base64Decoder(
            new PK_DecryptorFilter(rng, dec, new StringSink(claro))
        )
    );
    return claro;
}

string cifrarRSAPrivado(const string& texto)
{
    // Cifrar con clave privada mediante firma digital PKCS1v15 + SHA256
    AutoSeededRandomPool rng;
    string cifrado;
    RSASS<PKCS1v15, SHA256>::Signer signer(g_privateKey);
    StringSource(texto, true,
        new SignerFilter(rng, signer,
            new Base64Encoder(new StringSink(cifrado))
        )
    );
    return cifrado;
}

// ============================================================
// MODULO 4: Guardar y cargar claves cifradas con DES-EDE
// ============================================================

void guardarClavePublica(const string& fichero, const string& passphrase)
{
    string claveSerial;
    StringSink ss(claveSerial);
    g_publicKey.Save(ss);

    string claveCifrada = cifrarDESEDE(claveSerial, passphrase);
    ofstream f(fichero);
    f << claveCifrada;
    f.close();
    cout << "OK: Clave publica guardada cifrada en: " << fichero << endl;
}

void guardarClavePrivada(const string& fichero, const string& passphrase)
{
    string claveSerial;
    StringSink ss(claveSerial);
    g_privateKey.Save(ss);

    string claveCifrada = cifrarDESEDE(claveSerial, passphrase);
    ofstream f(fichero);
    f << claveCifrada;
    f.close();
    cout << "OK: Clave privada guardada cifrada en: " << fichero << endl;
}

void cargarClavePublica(const string& fichero, const string& passphrase)
{
    ifstream f(fichero);
    string claveCifrada((istreambuf_iterator<char>(f)),
        istreambuf_iterator<char>());
    f.close();

    string claveSerial = descifrarDESEDE(claveCifrada, passphrase);
    StringSource ss(claveSerial, true);
    g_publicKey.Load(ss);
    g_tengoClaves = true;
    cout << "OK: Clave publica cargada desde: " << fichero << endl;
}

void cargarClavePrivada(const string& fichero, const string& passphrase)
{
    ifstream f(fichero);
    string claveCifrada((istreambuf_iterator<char>(f)),
        istreambuf_iterator<char>());
    f.close();

    string claveSerial = descifrarDESEDE(claveCifrada, passphrase);
    StringSource ss(claveSerial, true);
    g_privateKey.Load(ss);
    g_tengoClaves = true;
    cout << "OK: Clave privada cargada desde: " << fichero << endl;
}

// ============================================================
// MODULO 5: Fecha/hora en ficheros
// ============================================================

string anadirFechaHora(const string& contenido)
{
    return getFechaHora() + "\n" + contenido;
}

pair<string, string> extraerFechaHora(const string& contenido)
{
    // Los primeros 19 caracteres son la fecha "YYYY/MM/DD_HH:MM:SS"
    if (contenido.size() > 20)
    {
        string fecha = contenido.substr(0, 19);
        string texto = contenido.substr(20); // salta fecha + '\n'
        return pair<string, string>(fecha, texto);
    }
    return pair<string, string>("(sin fecha)", contenido);
}

// ============================================================
// MENU
// ============================================================

void mostrarMenu()
{
    cout << "\n================================================\n";
    cout << "    HERRAMIENTA CRIPTOGRAFICA - UMH P2S2\n";
    cout << "================================================\n";
    cout << "  --- SIMETRICO ---\n";
    cout << "  1.  Cifrar texto con DES-EDE CBC\n";
    cout << "  2.  Descifrar texto con DES-EDE CBC\n";
    cout << "  3.  Cifrar fichero con DES-EDE CBC\n";
    cout << "  4.  Descifrar fichero con DES-EDE CBC\n";
    cout << "  5.  Cifrar texto con AES-GCM\n";
    cout << "  6.  Descifrar texto con AES-GCM\n";
    cout << "  7.  Cifrar fichero con AES-GCM\n";
    cout << "  8.  Descifrar fichero con AES-GCM\n";
    cout << "  --- ASIMETRICO RSA ---\n";
    cout << "  9.  Generar par de claves RSA\n";
    cout << "  10. Guardar clave publica (cifrada DES-EDE)\n";
    cout << "  11. Guardar clave privada (cifrada DES-EDE)\n";
    cout << "  12. Cargar clave publica\n";
    cout << "  13. Cargar clave privada\n";
    cout << "  14. Cifrar texto con clave publica RSA\n";
    cout << "  15. Descifrar texto con clave privada RSA\n";
    cout << "  16. Cifrar fichero con clave privada RSA\n";
    cout << "      (aniade fecha/hora al principio)\n";
    cout << "  17. Descifrar fichero con clave publica RSA\n";
    cout << "      (muestra y elimina fecha/hora)\n";
    cout << "  0.  Salir\n";
    cout << "================================================\n";
    cout << "Opcion: ";
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[])
{
    int opcion = -1;

    do {
        mostrarMenu();
        cin >> opcion;
        cin.ignore();

        try {
            switch (opcion)
            {
                // --- DES-EDE texto ---
            case 1: {
                string texto, pp;
                cout << "Texto a cifrar: ";
                getline(cin, texto);
                cout << "Passphrase: ";
                getline(cin, pp);
                cout << "\nCifrado:\n" << cifrarDESEDE(texto, pp) << endl;
                break;
            }
            case 2: {
                string cifrado, pp;
                cout << "Texto cifrado (Base64): ";
                getline(cin, cifrado);
                cout << "Passphrase: ";
                getline(cin, pp);
                cout << "\nDescifrado: " << descifrarDESEDE(cifrado, pp) << endl;
                break;
            }
                  // --- DES-EDE fichero ---
            case 3: {
                string entrada, salida, pp;
                cout << "Fichero entrada: ";
                getline(cin, entrada);
                cout << "Fichero salida: ";
                getline(cin, salida);
                cout << "Passphrase: ";
                getline(cin, pp);

                ifstream fin(entrada);
                string contenido((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                ofstream fout(salida);
                fout << cifrarDESEDE(contenido, pp);
                fout.close();
                cout << "OK: Fichero cifrado guardado en: " << salida << endl;
                break;
            }
            case 4: {
                string entrada, salida, pp;
                cout << "Fichero cifrado: ";
                getline(cin, entrada);
                cout << "Fichero salida: ";
                getline(cin, salida);
                cout << "Passphrase: ";
                getline(cin, pp);

                ifstream fin(entrada);
                string contenido((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                ofstream fout(salida);
                fout << descifrarDESEDE(contenido, pp);
                fout.close();
                cout << "OK: Fichero descifrado guardado en: " << salida << endl;
                break;
            }
                  // --- AES-GCM texto ---
            case 5: {
                string texto, claveHex, ivHex, cifradoB64;
                cout << "Texto a cifrar: ";
                getline(cin, texto);
                cifrarAESGCM(texto, claveHex, ivHex, cifradoB64);
                cout << "\nCifrado (Base64):\n" << cifradoB64 << endl;
                cout << "Clave (hex): " << claveHex << endl;
                cout << "IV (hex): " << ivHex << endl;
                break;
            }
            case 6: {
                string cifrado, claveHex, ivHex;
                cout << "Texto cifrado (Base64): ";
                getline(cin, cifrado);
                cout << "Clave (hex): ";
                getline(cin, claveHex);
                cout << "IV (hex): ";
                getline(cin, ivHex);
                cout << "\nDescifrado: "
                    << descifrarAESGCM(cifrado, claveHex, ivHex) << endl;
                break;
            }
                  // --- AES-GCM fichero ---
            case 7: {
                string entrada, salidaCifrado, salidaClave, salidaIV;
                string claveHex, ivHex, cifradoB64;
                cout << "Fichero entrada: ";
                getline(cin, entrada);
                cout << "Fichero cifrado salida: ";
                getline(cin, salidaCifrado);
                cout << "Fichero clave salida: ";
                getline(cin, salidaClave);
                cout << "Fichero IV salida: ";
                getline(cin, salidaIV);

                ifstream fin(entrada);
                string contenido((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                cifrarAESGCM(contenido, claveHex, ivHex, cifradoB64);

                ofstream fc(salidaCifrado); fc << cifradoB64; fc.close();
                ofstream fk(salidaClave);   fk << claveHex;   fk.close();
                ofstream fi(salidaIV);      fi << ivHex;      fi.close();
                cout << "OK: Ficheros guardados correctamente." << endl;
                break;
            }
            case 8: {
                string entrada, salida, claveHex, ivHex;
                cout << "Fichero cifrado: ";
                getline(cin, entrada);
                cout << "Fichero salida: ";
                getline(cin, salida);
                cout << "Clave (hex): ";
                getline(cin, claveHex);
                cout << "IV (hex): ";
                getline(cin, ivHex);

                ifstream fin(entrada);
                string cifrado((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                ofstream fout(salida);
                fout << descifrarAESGCM(cifrado, claveHex, ivHex);
                fout.close();
                cout << "OK: Fichero descifrado guardado en: " << salida << endl;
                break;
            }
                  // --- RSA ---
            case 9:
                generarParClaves();
                break;

            case 10: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves (opcion 9).\n";
                    break;
                }
                string fichero, pp;
                cout << "Nombre fichero: ";
                getline(cin, fichero);
                cout << "Passphrase: ";
                getline(cin, pp);
                guardarClavePublica(fichero, pp);
                break;
            }
            case 11: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves (opcion 9).\n";
                    break;
                }
                string fichero, pp;
                cout << "Nombre fichero: ";
                getline(cin, fichero);
                cout << "Passphrase: ";
                getline(cin, pp);
                guardarClavePrivada(fichero, pp);
                break;
            }
            case 12: {
                string fichero, pp;
                cout << "Nombre fichero: ";
                getline(cin, fichero);
                cout << "Passphrase: ";
                getline(cin, pp);
                cargarClavePublica(fichero, pp);
                break;
            }
            case 13: {
                string fichero, pp;
                cout << "Nombre fichero: ";
                getline(cin, fichero);
                cout << "Passphrase: ";
                getline(cin, pp);
                cargarClavePrivada(fichero, pp);
                break;
            }
            case 14: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves.\n";
                    break;
                }
                string texto;
                cout << "Texto a cifrar: ";
                getline(cin, texto);
                cout << "\nCifrado:\n" << cifrarRSAPublico(texto) << endl;
                break;
            }
            case 15: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves.\n";
                    break;
                }
                string cifrado;
                cout << "Texto cifrado (Base64): ";
                getline(cin, cifrado);
                cout << "\nDescifrado: " << descifrarRSAPrivado(cifrado) << endl;
                break;
            }
                   // --- RSA fichero con fecha/hora ---
            case 16: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves.\n";
                    break;
                }
                string entrada, salida;
                cout << "Fichero entrada: ";
                getline(cin, entrada);
                cout << "Fichero salida: ";
                getline(cin, salida);

                ifstream fin(entrada);
                string contenido((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                string conFecha = anadirFechaHora(contenido);
                cout << "Fecha/hora anadida: " << getFechaHora() << endl;

                string cifrado = cifrarRSAPrivado(conFecha);
                ofstream fout(salida);
                fout << cifrado;
                fout.close();
                cout << "OK: Fichero cifrado con clave privada: " << salida << endl;
                break;
            }
            case 17: {
                if (!g_tengoClaves) {
                    cout << "AVISO: Primero genera o carga las claves.\n";
                    break;
                }
                string entrada, salida;
                cout << "Fichero cifrado: ";
                getline(cin, entrada);
                cout << "Fichero salida: ";
                getline(cin, salida);

                ifstream fin(entrada);
                string cifrado((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
                fin.close();

                string descifrado = descifrarRSAPrivado(cifrado);

                pair<string, string> resultado = extraerFechaHora(descifrado);
                string fecha = resultado.first;
                string texto = resultado.second;

                cout << "\nFecha/hora de cifrado: " << fecha << endl;

                ofstream fout(salida);
                fout << texto;
                fout.close();
                cout << "OK: Fichero descifrado (sin fecha) guardado en: " << salida << endl;
                break;
            }
            case 0:
                cout << "Saliendo...\n";
                break;
            default:
                cout << "Opcion no valida.\n";
            }
        }
        catch (const Exception& e) {
            cerr << "\nERROR Crypto++: " << e.what() << endl;
        }
        catch (const exception& e) {
            cerr << "\nERROR: " << e.what() << endl;
        }

    } while (opcion != 0);

    return 0;
}