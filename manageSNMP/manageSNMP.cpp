#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <winsock2.h>
#include <windows.h>
#include <snmp.h>
#include <mgmtapi.h>

#pragma comment(lib, "snmpapi.lib")
#pragma comment(lib, "mgmtapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Функция для преобразования строки OID в массив UINT
bool ParseOIDString(const std::string& oidStr, std::vector<UINT>& oidArray) {
    std::istringstream iss(oidStr);
    std::string token;
    oidArray.clear();

    while (std::getline(iss, token, '.')) {
        if (token.empty()) continue;

        for (char c : token) {
            if (!isdigit(c)) {
                std::cerr << "Invalid OID format: non-digit character found" << std::endl;
                return false;
            }
        }

        try {
            UINT value = std::stoul(token);
            oidArray.push_back(value);
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing OID component: " << token << std::endl;
            return false;
        }
    }

    if (oidArray.empty()) {
        std::cerr << "OID is empty" << std::endl;
        return false;
    }

    return true;
}

// Функция для преобразования кода ошибки в текст
const char* SnmpErrorToString(AsnInteger error) {
    switch (error) {
    case SNMP_ERRORSTATUS_NOERROR: return "No error";
    case SNMP_ERRORSTATUS_TOOBIG: return "Too big";
    case SNMP_ERRORSTATUS_NOSUCHNAME: return "No such name";
    case SNMP_ERRORSTATUS_BADVALUE: return "Bad value";
    case SNMP_ERRORSTATUS_READONLY: return "Read only";
    case SNMP_ERRORSTATUS_GENERR: return "General error";
    case SNMP_ERRORSTATUS_NOACCESS: return "No access";
    case SNMP_ERRORSTATUS_WRONGTYPE: return "Wrong type";
    case SNMP_ERRORSTATUS_WRONGLENGTH: return "Wrong length";
    case SNMP_ERRORSTATUS_WRONGENCODING: return "Wrong encoding";
    case SNMP_ERRORSTATUS_WRONGVALUE: return "Wrong value";
    case SNMP_ERRORSTATUS_NOCREATION: return "No creation";
    case SNMP_ERRORSTATUS_INCONSISTENTVALUE: return "Inconsistent value";
    case SNMP_ERRORSTATUS_RESOURCEUNAVAILABLE: return "Resource unavailable";
    case SNMP_ERRORSTATUS_COMMITFAILED: return "Commit failed";
    case SNMP_ERRORSTATUS_UNDOFAILED: return "Undo failed";
    case SNMP_ERRORSTATUS_AUTHORIZATIONERROR: return "Authorization error";
    case SNMP_ERRORSTATUS_NOTWRITABLE: return "Not writable";
    case SNMP_ERRORSTATUS_INCONSISTENTNAME: return "Inconsistent name";
    default: return "Unknown error";
    }
}

// Функция для печати значения SNMP
void PrintSnmpValue(const AsnAny& value) {
    switch (value.asnType) {
    case ASN_INTEGER:
        std::cout << "INTEGER: " << value.asnValue.number << std::endl;
        break;
    case ASN_COUNTER32:
        std::cout << "COUNTER32: " << value.asnValue.number << std::endl;
        break;
    case ASN_GAUGE32:
        std::cout << "GAUGE: " << value.asnValue.unsigned32 << std::endl;
        break;
    case ASN_OCTETSTRING:
        std::cout << "OCTET STRING: ";
        // Проверяем, может ли это быть MAC-адрес (6 байт)
        if (value.asnValue.string.length == 6) {
            // Выводим как MAC-адрес в формате XX-XX-XX-XX-XX-XX
            for (DWORD i = 0; i < value.asnValue.string.length; i++) {
                unsigned char byte = value.asnValue.string.stream[i];
                std::cout << std::hex << std::uppercase << (int)byte;
                if ((int)byte == 0) {
                    std::cout << std::hex << std::uppercase << (int)byte;
                }
                if (i < value.asnValue.string.length - 1) {
                    std::cout << "-";
                }
            }
            std::cout << std::dec;
        }
        // Проверяем, может ли это быть IP-адрес (4 байта)
        else if (value.asnValue.string.length == 4) {
            // Выводим как IP-адрес
            for (DWORD i = 0; i < value.asnValue.string.length; i++) {
                std::cout << (int)value.asnValue.string.stream[i];
                if (i < value.asnValue.string.length - 1) {
                    std::cout << ".";
                }
            }
        }
        else {
            // Проверяем, содержит ли строка только печатаемые символы
            bool allPrintable = true;
            for (DWORD i = 0; i < value.asnValue.string.length; i++) {
                if (!isprint(value.asnValue.string.stream[i])) {
                    allPrintable = false;
                    break;
                }
            }

            if (allPrintable && value.asnValue.string.length > 0) {
                // Выводим как обычную строку
                for (DWORD i = 0; i < value.asnValue.string.length; i++) {
                    std::cout << value.asnValue.string.stream[i];
                }
            }
            else {
                // Выводим в hex формате
                for (DWORD i = 0; i < value.asnValue.string.length; i++) {
                    unsigned char byte = value.asnValue.string.stream[i];
                    std::cout << std::hex << std::uppercase << (int)byte;
                    if (i < value.asnValue.string.length - 1) {
                        std::cout << " ";
                    }
                }
                std::cout << std::dec;
            }
        }
        break;
    case ASN_OBJECTIDENTIFIER:
        std::cout << "OID: ";
        for (UINT i = 0; i < value.asnValue.object.idLength; i++) {
            std::cout << value.asnValue.object.ids[i];
            if (i < value.asnValue.object.idLength - 1) std::cout << ".";
        }
        LPSTR str_oid;
        AsnObjectIdentifier oids = value.asnValue.object;
        SnmpMgrOidToStr(&oids, &str_oid);
        std::cout << "\t" << str_oid << "\t";
        std::cout << std::endl;
        break;
    case ASN_NULL:
        std::cout << "NULL" << std::endl;
        break;
    case ASN_RFC1155_IPADDRESS:
        std::cout << "IPADDRESS: "
            << (int)value.asnValue.address.stream[0] << "."
            << (int)value.asnValue.address.stream[1] << "."
            << (int)value.asnValue.address.stream[2] << "."
            << (int)value.asnValue.address.stream[3] << std::endl;
        break;
    case ASN_TIMETICKS:
        std::cout << "TIMETICKS: " << value.asnValue.ticks << std::endl;
        break;
    default:
        std::cout << "UNKNOWN TYPE: " << value.asnType << std::endl;
        break;
    }
}

// Функция для выполнения SNMP GET запроса
//bool SnmpGetRequest(HANDLE hSnmp, const std::vector<UINT>& oidArray, AsnAny& result) {
//    AsnObjectIdentifier reqObject;
//    RFC1157VarBindList varBindList;
//    AsnInteger errorStatus;
//    AsnInteger errorIndex;
//
//    // Настройка OID
//    reqObject.idLength = (UINT)oidArray.size();
//    reqObject.ids = (UINT*)SnmpUtilMemAlloc(oidArray.size() * sizeof(UINT));
//
//    if (!reqObject.ids) return false;
//
//    // Копируем OID
//    for (size_t i = 0; i < oidArray.size(); i++) {
//        reqObject.ids[i] = oidArray[i];
//    }
//
//    // Настройка переменных
//    varBindList.list = (RFC1157VarBind*)SnmpUtilMemAlloc(sizeof(RFC1157VarBind));
//    if (!varBindList.list) {
//        return false;
//    }
//
//    varBindList.len = 1;
//
//    // Инициализация varBind
//    varBindList.list[0].name = reqObject;
//    varBindList.list[0].value.asnType = ASN_NULL;
//
//    // Выполнение SNMP-запроса
//    bool success = false;
//
//    // Сбрасываем ошибку перед запросом
//    SetLastError(0);
//
//    std::cout << "Sending SNMP GET request..." << std::endl;
//
//    if (SnmpMgrRequest(hSnmp, SNMP_PDU_GET, &varBindList, &errorStatus, &errorIndex)) {
//        if (errorStatus == SNMP_ERRORSTATUS_NOERROR) {
//            // Копируем результат
//            result = varBindList.list[0].value;
//            success = true;
//            std::cout << "SNMP request successful" << std::endl;
//        }
//        else {
//            std::cout << "SNMP Error: " << SnmpErrorToString(errorStatus)
//                << " (code: " << errorStatus << ")" << std::endl;
//        }
//    }
//    else {
//        DWORD lastError = GetLastError();
//        std::cerr << "SnmpMgrRequest failed. System error: " << lastError << std::endl;
//    }
//
//    // Очистка памяти
//    if (varBindList.list) {
//        if (varBindList.list[0].name.ids) {
//            SnmpUtilMemFree(varBindList.list[0].name.ids);
//        }
//        // Освобождаем значение, если оно было выделено SNMP
//        //SnmpUtilMemFree(&varBindList.list[0]);
//        SnmpUtilMemFree(varBindList.list);
//    }
//    //SnmpUtilOidFree(&reqObject);
//
//    return success;
//}
//
//int main() {
//    // Инициализация Winsock
//    WSADATA wsaData;
//    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
//        std::cerr << "WSAStartup failed" << std::endl;
//        return 1;
//    }
//
//    // Параметры подключения
//    std::string hostname, community, oidString;
//
//    std::cout << "=== SNMP GET Client ===" << std::endl;
//
//    // Ввод параметров
//    std::cout << "Enter SNMP host [demo.pysnmp.com]: ";
//    std::getline(std::cin, hostname);
//    if (hostname.empty()) hostname = "demo.pysnmp.com";
//
//    std::cout << "Enter community string [public]: ";
//    std::getline(std::cin, community);
//    if (community.empty()) community = "public";
//
//    // Открываем SNMP сессию с ПРАВИЛЬНЫМИ параметрами
//    std::cout << "Connecting to " << hostname << " with community '" << community << "'..." << std::endl;
//
//    // КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Правильный вызов SnmpMgrOpen
//    HANDLE hSnmp = SnmpMgrOpen(
//        const_cast<LPSTR>(hostname.c_str()),
//        const_cast<LPSTR>(community.c_str()),
//        5000,  // timeout в миллисекундах
//        2     // количество повторных попыток
//    );
//
//    if (hSnmp == NULL) {
//        DWORD error = GetLastError();
//        std::cerr << "SnmpMgrOpen failed. Error code: " << error << std::endl;
//
//        if (error == 1231) {
//            std::cerr << "Network error: Cannot reach the SNMP agent." << std::endl;
//        }
//
//        WSACleanup();
//        return 1;
//    }
//
//    std::cout << "SNMP session opened successfully!" << std::endl;
//    std::cout << "\nAvailable OID examples:" << std::endl;
//    std::cout << "1.3.6.1.2.1.1.1.0 - System description" << std::endl;
//    std::cout << "1.3.6.1.2.1.1.3.0 - System uptime" << std::endl;
//    std::cout << "1.3.6.1.2.1.1.5.0 - System name" << std::endl;
//    std::cout << "1.3.6.1.2.1.2.1.0 - Number of network interfaces" << std::endl;
//
//    // Основной цикл запросов
//    while (true) {
//        std::cout << "\nEnter OID (or 'quit' to exit): ";
//        std::getline(std::cin, oidString);
//
//        if (oidString == "quit" || oidString == "exit") {
//            break;
//        }
//
//        if (oidString.empty()) {
//            continue;
//        }
//
//        // Парсинг OID
//        std::vector<UINT> oidArray;
//        if (!ParseOIDString(oidString, oidArray)) {
//            std::cerr << "Invalid OID format. Use format: 1.3.6.1.2.1.1.1.0" << std::endl;
//            continue;
//        }
//
//        std::cout << "Sending GET request for OID: ";
//        for (size_t i = 0; i < oidArray.size(); i++) {
//            std::cout << oidArray[i];
//            if (i < oidArray.size() - 1) std::cout << ".";
//        }
//        std::cout << std::endl;
//
//        // Выполнение запроса
//        AsnAny result;
//        if (SnmpGetRequest(hSnmp, oidArray, result)) {
//            std::cout << "Response: ";
//            PrintSnmpValue(result);
//        }
//        else {
//            std::cout << "Failed to get response for OID" << std::endl;
//        }
//    }
//
//    // Закрытие сессии
//    SnmpMgrClose(hSnmp);
//    WSACleanup();
//
//    std::cout << "Program completed" << std::endl;
//    return 0;
//}

// Функция для сравнения двух OID
bool CompareOID(const AsnObjectIdentifier& oid1, const AsnObjectIdentifier& oid2) {
    if (oid1.idLength != oid2.idLength) return false;
    for (UINT i = 0; i < oid1.idLength; i++) {
        if (oid1.ids[i] != oid2.ids[i]) return false;
    }
    return true;
}

// Функция для выполнения SNMP WALK
bool SnmpWalkRequest(HANDLE hSnmp, const std::vector<UINT>& baseOidArray) {
    AsnObjectIdentifier baseOid;
    RFC1157VarBindList varBindList;
    AsnInteger errorStatus;
    AsnInteger errorIndex;

    // Настройка базового OID
    baseOid.idLength = (UINT)baseOidArray.size();
    baseOid.ids = (UINT*)SnmpUtilMemAlloc(baseOidArray.size() * sizeof(UINT));
    if (!baseOid.ids) return false;

    for (size_t i = 0; i < baseOidArray.size(); i++) {
        baseOid.ids[i] = baseOidArray[i];
    }

    // Начальная настройка переменных
    varBindList.list = (RFC1157VarBind*)SnmpUtilMemAlloc(sizeof(RFC1157VarBind));
    if (!varBindList.list) {
        SnmpUtilMemFree(baseOid.ids);
        return false;
    }
    varBindList.len = 1;

    // Инициализация начального varBind
    varBindList.list[0].name = baseOid;
    varBindList.list[0].value.asnType = ASN_NULL;

    std::cout << "\n=== SNMP GET SUBTREE Results for OID: ";
    for (size_t i = 0; i < baseOidArray.size(); i++) {
        std::cout << baseOidArray[i];
        if (i < baseOidArray.size() - 1) std::cout << ".";
    }
    std::cout << " ===" << std::endl;

    int itemCount = 0;
    bool moreItems = true;
    AsnObjectIdentifier lastOid = baseOid;

    while (moreItems) {
        // Выполнение GETNEXT запроса
        if (SnmpMgrRequest(hSnmp, SNMP_PDU_GETNEXT, &varBindList, &errorStatus, &errorIndex)) {
            if (errorStatus == SNMP_ERRORSTATUS_NOERROR) {
                // Проверяем, находится ли полученный OID в нужном поддереве
                bool isInSubtree = true;
                UINT minLength = min(lastOid.idLength, varBindList.list[0].name.idLength);

                for (UINT i = 0; i < minLength; i++) {
                    if (varBindList.list[0].name.ids[i] != lastOid.ids[i]) {
                        if (i < baseOid.idLength) {
                            isInSubtree = false;
                        }
                        break;
                    }
                }

                if (!isInSubtree || CompareOID(varBindList.list[0].name, lastOid)) {
                    moreItems = false;
                    break;
                }

                // Выводим результат
                itemCount++;
                std::cout << itemCount << ". OID: ";
                for (UINT i = 0; i < varBindList.list[0].name.idLength; i++) {
                    std::cout << varBindList.list[0].name.ids[i];
                    if (i < varBindList.list[0].name.idLength - 1) std::cout << ".";
                }
                LPSTR str_oid;
                SnmpMgrOidToStr(&varBindList.list[0].name, &str_oid);
                std::cout << "\t" << str_oid << "\t";
                std::cout << " = ";
                PrintSnmpValue(varBindList.list[0].value);
                std::cout << std::endl;

                // Сохраняем последний OID для следующей итерации
                /*if (lastOid.ids) {
                    SnmpUtilMemFree(lastOid.ids);
                }*/
                lastOid = varBindList.list[0].name;
                lastOid.ids = (UINT*)SnmpUtilMemAlloc(lastOid.idLength * sizeof(UINT));
                for (UINT i = 0; i < lastOid.idLength; i++) {
                    lastOid.ids[i] = varBindList.list[0].name.ids[i];
                }

                // Подготавливаем varBind для следующего запроса
                varBindList.list[0].name = lastOid;
            }
            else {
                LPSTR str_oid;
                SnmpMgrOidToStr(&varBindList.list[0].name, &str_oid);
                std::cout << "SNMP Error: " << SnmpErrorToString(errorStatus)
                    << " (code: " << errorStatus << ") " << "for OID: " << str_oid << std::endl;
                moreItems = false;
            }
        }
        else {
            DWORD lastError = GetLastError();
            std::cerr << "SnmpMgrRequest failed. System error: " << lastError << std::endl;
            moreItems = false;
        }
    }

    std::cout << "=== Found " << itemCount << " items ===" << std::endl;

    // Очистка памяти
    /*if (lastOid.ids) {
        SnmpUtilMemFree(lastOid.ids);
    }*/
    if (varBindList.list) {
        SnmpUtilMemFree(varBindList.list);
    }
    //SnmpUtilMemFree(baseOid.ids);

    return itemCount > 0;
}

// Функция для выполнения SNMP GET запроса (оставлена для обратной совместимости)
bool SnmpGetRequest(HANDLE hSnmp, const std::vector<UINT>& oidArray, AsnAny& result) {
    AsnObjectIdentifier reqObject;
    RFC1157VarBindList varBindList;
    AsnInteger errorStatus;
    AsnInteger errorIndex;

    // Настройка OID
    reqObject.idLength = (UINT)oidArray.size();
    reqObject.ids = (UINT*)SnmpUtilMemAlloc(oidArray.size() * sizeof(UINT));
    if (!reqObject.ids) return false;

    for (size_t i = 0; i < oidArray.size(); i++) {
        reqObject.ids[i] = oidArray[i];
    }

    varBindList.list = (RFC1157VarBind*)SnmpUtilMemAlloc(sizeof(RFC1157VarBind));
    if (!varBindList.list) {
        SnmpUtilMemFree(reqObject.ids);
        return false;
    }

    varBindList.len = 1;
    varBindList.list[0].name = reqObject;
    varBindList.list[0].value.asnType = ASN_NULL;

    bool success = false;

    LPSTR str_oid;
    SnmpMgrOidToStr(&reqObject, &str_oid);
    std::cout << "Name of element (from OID): " << str_oid << "\n";

    SetLastError(0);

    if (SnmpMgrRequest(hSnmp, SNMP_PDU_GET, &varBindList, &errorStatus, &errorIndex)) {
        if (errorStatus == SNMP_ERRORSTATUS_NOERROR) {
            result = varBindList.list[0].value;
            success = true;
        }
        else {
            std::cout << "SNMP Error: " << SnmpErrorToString(errorStatus)
                << " (code: " << errorStatus << ")" << std::endl;
        }
    }
    else {
        DWORD lastError = GetLastError();
        std::cerr << "SnmpMgrRequest failed. System error: " << lastError << std::endl;
    }

    // Очистка памяти
    if (varBindList.list) {
        if (varBindList.list[0].name.ids) {
            SnmpUtilMemFree(varBindList.list[0].name.ids);
        }
        SnmpUtilMemFree(varBindList.list);
    }

    return success;
}

int main() {
    // Инициализация Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    // Параметры подключения
    std::string hostname, community;

    std::cout << "=== SNMP GET/GET SUBTREE Client ===" << std::endl;

    // Ввод параметров
    std::cout << "Enter SNMP host [demo.pysnmp.com]: ";
    std::getline(std::cin, hostname);
    if (hostname.empty()) hostname = "demo.pysnmp.com";

    std::cout << "Enter community string [public]: ";
    std::getline(std::cin, community);
    if (community.empty()) community = "public";

    // Открываем SNMP сессию
    std::cout << "Connecting to " << hostname << " with community '" << community << "'..." << std::endl;

    HANDLE hSnmp = SnmpMgrOpen(
        const_cast<LPSTR>(hostname.c_str()),
        const_cast<LPSTR>(community.c_str()),
        5000,
        2
    );

    if (hSnmp == NULL) {
        DWORD error = GetLastError();
        std::cerr << "SnmpMgrOpen failed. Error code: " << error << std::endl;

        if (error == 1231) {
            std::cerr << "Network error: Cannot reach the SNMP agent." << std::endl;
        }

        WSACleanup();
        return 1;
    }

    std::cout << "SNMP session opened successfully!" << std::endl;

    std::cout << "\nAvailable OID examples for GET SUBTREE:" << std::endl;
    std::cout << "1.3.6.1.2.1.1     - System group (complete system info)" << std::endl;
    std::cout << "1.3.6.1.2.1.2     - Interfaces group (network interfaces)" << std::endl;
    std::cout << "1.3.6.1.2.1.4     - IP group" << std::endl;
    std::cout << "1.3.6.1.2.1.5     - ICMP group" << std::endl;
    std::cout << "\nFor single value GET requests, use specific OIDs:" << std::endl;
    std::cout << "1.3.6.1.2.1.1.1.0 - System description" << std::endl;
    std::cout << "1.3.6.1.2.1.1.3.0 - System uptime" << std::endl;

    // Основной цикл запросов
    while (true) {
        std::string input;
        std::cout << "\nEnter OID for GET, 'get_subtree <OID>' for GET SUBTREE, or 'quit' to exit: ";
        std::getline(std::cin, input);

        if (input == "quit" || input == "exit") {
            break;
        }

        if (input.empty()) {
            continue;
        }

        // Обработка WALK команды
        if (input.back() != '0') {
            std::string oidString = input;

            std::vector<UINT> oidArray;
            if (!ParseOIDString(oidString, oidArray)) {
                std::cerr << "Invalid OID format. Use format: 1.3.6.1.2.1.1" << std::endl;
                continue;
            }

            SnmpWalkRequest(hSnmp, oidArray);
        }
        else {
            // Обычный GET запрос
            std::vector<UINT> oidArray;
            if (!ParseOIDString(input, oidArray)) {
                std::cerr << "Invalid OID format. Use format: 1.3.6.1.2.1.1.1.0" << std::endl;
                continue;
            }

            std::cout << "Sending GET request for OID: ";
            for (size_t i = 0; i < oidArray.size(); i++) {
                std::cout << oidArray[i];
                if (i < oidArray.size() - 1) std::cout << ".";
            }
            std::cout << std::endl;

            AsnAny result;
            if (SnmpGetRequest(hSnmp, oidArray, result)) {
                std::cout << "Response: ";
                PrintSnmpValue(result);
                std::cout << std::endl;
            }
            else {
                std::cout << "Failed to get response for OID" << std::endl;
            }
        }
    }

    // Закрытие сессии
    SnmpMgrClose(hSnmp);
    WSACleanup();

    std::cout << "Program completed" << std::endl;
    return 0;
}