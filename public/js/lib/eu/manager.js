//=============================================================================

var URL_GET_CERTIFICATES = "/data/CACertificates.p7b?version=1.0.5";
var URL_CAS = "/data/CAs.json?version=1.0.5";
var URL_XML_HTTP_PROXY_SERVICE = "https://vpn.unity-bars.com.ua:40103/proxy/ProxyHandler.ashx";

//=============================================================================

var EUSignCPTest = NewClass({
        "Vendor": "JSC IIT",
        "ClassVersion": "1.0.0",
        "ClassName": "EUSignCPTest",
        "CertsLocalStorageName": "Certificates",
        "CRLsLocalStorageName": "CRLs",
        "recepientsCertsIssuers": null,
        "recepientsCertsSerials": null,
        "PrivateKeyNameSessionStorageName": "PrivateKeyName",
        "PrivateKeySessionStorageName": "PrivateKey",
        "PrivateKeyPasswordSessionStorageName": "PrivateKeyPassword",
        "PrivateKeyCertificatesSessionStorageName": "PrivateKeyCertificates",
        "PrivateKeyCertificatesChainSessionStorageName": "PrivateKeyCertificatesChain",
        "CACertificatesSessionStorageName": "CACertificates",
        "CAServerIndexSessionStorageName": "CAServerIndex",
        "CAsServers": null,
        "CAServer": null,
        "offline": false,
        "useCMP": false,
        "loadPKCertsFromFile": false,
        "privateKeyCerts": null,
        // ui elements euSignTest.uiCertList
        "uiVerifyBtn": document.getElementById('VerifyDataButton'), // кнопка проверки подписи
        "uiSignBtn": document.getElementById('SignDataButton'), // кнопка наложения подписи
        "uiPkSelectBtn": document.getElementById('PKeySelectFileButton'), // кнопка выбора файла ключа
        "uiPkFileName": document.getElementById('PKeyFileName'), // поле с файлом ключа
        "uiPkCertsDiv": document.getElementById('PKCertsSelectZone'), // блок с загрузкой личных сертификатов
        "uiCaServersSelect": document.getElementById('CAsServersSelect'), // dropdown со списком ЦСК
        "uiPkStatusInfo": document.getElementById('PKStatusInfo'), // span для сообщений о процессе работы с ключем
        "uiPkPassword": document.getElementById('PKeyPassword'), // поле пароля для ключа
        "uiPkReadBtn": document.getElementById('PKeyReadButton'), // кнопка чтения ключа
        "uiPkFileInput": document.getElementById('PKeyFileInput'), // input(type=file) для загрузки ключа
        "uiCertInfo": document.getElementById('certInfo'), // блок с информацией о сертификате
        "uiVerifyErrorInfo": document.getElementById('verificationError'), // блок с информацией о неверной подписи
        "uiVerifyDiffInfo": document.getElementById('verificationErrorDiff'), // блок с информацией о различиях данных
        "uiVerifySuccessInfo": document.getElementById('verificationSuccess'), // блок с информацией о успешной проверке подписи
        "uiCertFileInput": document.getElementById('ChoosePKCertsInput'),// input(type=file) для загрузки сертификата
        "uiCertList": document.getElementById('SelectedPKCertsList') // output для отображения загруженого сертификата

    },
    function () {
    },
    {
        initialize: function () {
            setStatus('ініціалізація');

            var _onSuccess = function () {
                try {
                    euSign.Initialize();
                    euSign.SetJavaStringCompliant(true);
                    euSign.SetCharset("UTF-16LE");

                    if (euSign.DoesNeedSetSettings()) {
                        euSignTest.setDefaultSettings();
                    }
                    euSignTest.loadCertsFromServer();
                    euSignTest.setCASettings(0);

                    euSignTest.setSelectPKCertificatesEvents();
                    if (utils.IsSessionStorageSupported()) {
                        var _readPrivateKeyAsStoredFile = function () {
                            euSignTest.readPrivateKeyAsStoredFile();
                        }
                        setTimeout(_readPrivateKeyAsStoredFile, 10);
                    }

                    setStatus('');
                } catch (e) {
                    console.log(e);
                    setStatus('не ініціалізовано');
                }
            };
            var _onError = function () {
                setStatus('Не ініціалізовано');
                alert('Виникла помилка ' +
                    'при завантаженні криптографічної бібліотеки');
            };

            euSignTest.loadCAsSettings(_onSuccess, _onError);
        },
        loadCAsSettings: function (onSuccess, onError) {
            var pThis = this;

            var _onSuccess = function (casResponse) {
                try {
                    var servers = JSON.parse(casResponse.replace(/\\'/g, "'"));

                    var select = euSignTest.uiCaServersSelect;
                    for (var i = 0; i < servers.length; i++) {
                        var option = document.createElement("option");
                        option.text = servers[i].issuerCNs[0];
                        select.add(option);
                    }

                    var option = document.createElement("option");
                    option.text = "Локальні сертифікати";
                    select.add(option);

                    select.onchange = function () {
                        pThis.setCASettings(select.selectedIndex);
                    };

                    pThis.CAsServers = servers;

                    onSuccess();
                } catch (e) {
                    console.log(e);
                    //throw e;
                    onError();
                }
            };
            euSign.LoadDataFromServer(URL_CAS, _onSuccess, onError, false);
        },
        loadCertsFromServer: function () {
            var certificates = utils.GetSessionStorageItem(
                euSignTest.CACertificatesSessionStorageName, true, false);
            if (certificates != null) {
                try {
                    euSign.SaveCertificates(certificates);
                    return;
                } catch (e) {
                    console.error(e);
                    alert("Виникла помилка при імпорті " +
                        "завантажених з сервера сертифікатів " +
                        "до файлового сховища");
                }
            }

            var _onSuccess = function (certificates) {
                try {
                    euSign.SaveCertificates(certificates);
                    utils.SetSessionStorageItem(
                        euSignTest.CACertificatesSessionStorageName,
                        certificates, false);
                } catch (e) {
                    console.error(e);
                    alert("Виникла помилка при імпорті " +
                        "завантажених з сервера сертифікатів " +
                        "до файлового сховища");
                }
            };

            var _onFail = function (errorCode) {
                console.log("Виникла помилка при завантаженні сертифікатів з сервера. " +
                    "(HTTP статус " + errorCode + ")");
            };

            utils.GetDataFromServerAsync(URL_GET_CERTIFICATES, _onSuccess, _onFail, true);
        },
        setDefaultSettings: function () {
            try {
                euSign.SetXMLHTTPProxyService(URL_XML_HTTP_PROXY_SERVICE);

                var settings = euSign.CreateFileStoreSettings();
                settings.SetPath("/certificates");
                settings.SetSaveLoadedCerts(true);
                euSign.SetFileStoreSettings(settings);

                settings = euSign.CreateProxySettings();
                euSign.SetProxySettings(settings);

                settings = euSign.CreateTSPSettings();
                euSign.SetTSPSettings(settings);

                settings = euSign.CreateOCSPSettings();
                euSign.SetOCSPSettings(settings);

                settings = euSign.CreateCMPSettings();
                euSign.SetCMPSettings(settings);

                settings = euSign.CreateLDAPSettings();
                euSign.SetLDAPSettings(settings);

                settings = euSign.CreateOCSPAccessInfoModeSettings();
                settings.SetEnabled(true);
                euSign.SetOCSPAccessInfoModeSettings(settings);

                var CAs = this.CAsServers;
                settings = euSign.CreateOCSPAccessInfoSettings();
                if (CAs) {
                    for (var i = 0; i < CAs.length; i++) {
                        settings.SetAddress(CAs[i].ocspAccessPointAddress);
                        settings.SetPort(CAs[i].ocspAccessPointPort);

                        for (var j = 0; j < CAs[i].issuerCNs.length; j++) {
                            settings.SetIssuerCN(CAs[i].issuerCNs[j]);
                            euSign.SetOCSPAccessInfoSettings(settings);
                        }
                    }
                }
            } catch (e) {
                console.error(e);
                alert("Виникла помилка при встановленні налашувань: " + e);
            }
        },
        setCASettings: function (caIndex) {
            try {
                var caServer = (caIndex < this.CAsServers.length) ? this.CAsServers[caIndex] : null;
                var offline = ((caServer == null) || (caServer.address == "")) ? true : false;
                var useCMP = (!offline && (caServer.cmpAddress != ""));
                var loadPKCertsFromFile = (caServer == null) || (!useCMP && !caServer.certsInKey);

                euSignTest.CAServer = caServer;
                euSignTest.offline = offline;
                euSignTest.useCMP = useCMP;
                euSignTest.loadPKCertsFromFile = loadPKCertsFromFile;

                var message = "Оберіть файл з особистим ключем (зазвичай з ім'ям Key-6.dat) та вкажіть пароль захисту";
                if (loadPKCertsFromFile) {
                    message += ", а також оберіть сертифікат(и) (зазвичай, з розширенням cer, crt)";
                }
                setKeyStatus(message, 'info');
                var settings;

                euSignTest.uiPkCertsDiv.hidden = loadPKCertsFromFile ? '' : 'hidden';
                euSignTest.clearPrivateKeyCertificatesList();

                settings = euSign.CreateTSPSettings();
                if (!offline) {
                    settings.SetGetStamps(true);
                    if (caServer.tspAddress != "") {
                        settings.SetAddress(caServer.tspAddress);
                        settings.SetPort(caServer.tspAddressPort);
                    } else {
                        settings.SetAddress('acskidd.gov.ua');
                        settings.SetPort('80');
                    }
                }
                euSign.SetTSPSettings(settings);

                settings = euSign.CreateOCSPSettings();
                if (!offline) {
                    settings.SetUseOCSP(true);
                    settings.SetBeforeStore(true);
                    settings.SetAddress(caServer.ocspAccessPointAddress);
                    settings.SetPort(caServer.ocspAccessPointPort);
                }
                euSign.SetOCSPSettings(settings);

                settings = euSign.CreateCMPSettings();
                settings.SetUseCMP(useCMP);
                if (useCMP) {
                    settings.SetAddress(caServer.cmpAddress);
                    settings.SetPort("80");
                }
                euSign.SetCMPSettings(settings);

                settings = euSign.CreateLDAPSettings();
                euSign.SetLDAPSettings(settings);
            } catch (e) {
                console.error(e);
                alert("Виникла помилка при встановленні налашувань: " + e);
            }
        },
//-----------------------------------------------------------------------------
        getCAServer: function () {
            var index = euSignTest.uiCaServersSelect.selectedIndex;

            if (index < euSignTest.CAsServers.length)
                return euSignTest.CAsServers[index];

            return null;
        },
        loadCAServer: function () {
            var index = utils.GetSessionStorageItem(
                euSignTest.CAServerIndexSessionStorageName, false, false);
            if (index != null) {
                euSignTest.uiCaServersSelect.selectedIndex =
                    parseInt(index);
                euSignTest.setCASettings(parseInt(index));
            }
        },
        storeCAServer: function () {
            var index = euSignTest.uiCaServersSelect.selectedIndex;
            return utils.SetSessionStorageItem(
                euSignTest.CAServerIndexSessionStorageName, index.toString(), false);
        },
        removeCAServer: function () {
            utils.RemoveSessionStorageItem(
                euSignTest.CAServerIndexSessionStorageName);
        },
//-----------------------------------------------------------------------------
        storePrivateKey: function (keyName, key, password, certificates) {
            if (!utils.SetSessionStorageItem(
                    euSignTest.PrivateKeyNameSessionStorageName, keyName, false) || !utils.SetSessionStorageItem(
                    euSignTest.PrivateKeySessionStorageName, key, false) || !utils.SetSessionStorageItem(
                    euSignTest.PrivateKeyPasswordSessionStorageName, password, true) || !euSignTest.storeCAServer()) {
                return false;
            }

            if (Array.isArray(certificates)) {
                if (!utils.SetSessionStorageItems(
                        euSignTest.PrivateKeyCertificatesSessionStorageName,
                        certificates, false)) {
                    return false;
                }
            } else {
                if (!utils.SetSessionStorageItem(
                        euSignTest.PrivateKeyCertificatesChainSessionStorageName,
                        certificates, false)) {
                    return false;
                }
            }

            return true;
        },
        removeStoredPrivateKey: function () {
            utils.RemoveSessionStorageItem(
                euSignTest.PrivateKeyNameSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignTest.PrivateKeySessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignTest.PrivateKeyPasswordSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignTest.PrivateKeyCertificatesChainSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignTest.PrivateKeyCertificatesSessionStorageName);

            euSignTest.removeCAServer();
        },
//-----------------------------------------------------------------------------
        selectPrivateKeyFile: function (event) {
            var enable = (event.target.files.length == 1);
            euSignTest.uiPkReadBtn.disabled = enable ? '' : 'disabled';
            euSignTest.uiPkPassword.disabled = enable ? '' : 'disabled';
            euSignTest.uiPkFileName.value = enable ? event.target.files[0].name : '';
            euSignTest.uiPkPassword.value = '';
        },
//-----------------------------------------------------------------------------
        getPrivateKeyCertificatesByCMP: function (key, password, onSuccess, onError) {
            try {
                var cmpAddress = euSignTest.getCAServer().cmpAddress + ":80";
                var keyInfo = euSign.GetKeyInfoBinary(key, password);

                onSuccess(euSign.GetCertificatesByKeyInfo(keyInfo, [cmpAddress]));
            } catch (e) {
                onError(e);
            }
        },
        getPrivateKeyCertificates: function (key, password, fromCache, onSuccess, onError) {
            var certificates;
            if (euSignTest.CAServer != null &&
                euSignTest.CAServer.certsInKey) {
                onSuccess([]);
                return;
            }

            if (fromCache) {
                if (euSignTest.useCMP) {
                    certificates = utils.GetSessionStorageItem(
                        euSignTest.PrivateKeyCertificatesChainSessionStorageName, true, false);
                } else if (euSignTest.loadPKCertsFromFile) {
                    certificates = utils.GetSessionStorageItems(
                        euSignTest.PrivateKeyCertificatesSessionStorageName, true, false)
                }

                onSuccess(certificates);
            } else if (euSignTest.useCMP) {
                euSignTest.getPrivateKeyCertificatesByCMP(
                    key, password, onSuccess, onError);
            } else if (euSignTest.loadPKCertsFromFile) {
                var _onSuccess = function (files) {
                    var certificates = [];
                    for (var i = 0; i < files.length; i++) {
                        certificates.push(files[i].data);
                    }

                    onSuccess(certificates);
                };
                euSign.ReadFiles(
                    euSignTest.privateKeyCerts,
                    _onSuccess, onError);
            }
        },
        readPrivateKey: function (keyName, key, password, certificates, fromCache) {
            var _onError = function (e) {
                setStatus('');
                var message = (e.message + '(' + e.errorCode + ')') ? (e.message) : (e);
                setKeyStatus(message, 'error');

                if (fromCache) {
                    euSignTest.removeStoredPrivateKey();
                    euSignTest.privateKeyReaded(false);
                }
            };

            if (certificates == null) {
                var _onGetCertificates = function (certs) {
                    if (certs == null) {
                        _onError(euSign.MakeError(EU_ERROR_CERT_NOT_FOUND));
                        return;
                    }
                    euSignTest.readPrivateKey(keyName, key, password, certs, fromCache);
                }

                euSignTest.getPrivateKeyCertificates(key, password, fromCache, _onGetCertificates, _onError);
                return;
            }

            try {
                if (Array.isArray(certificates)) {
                    for (var i = 0; i < certificates.length; i++) {
                        euSign.SaveCertificate(certificates[i]);
                    }
                } else {
                    euSign.SaveCertificates(certificates);
                }

                euSign.ReadPrivateKeyBinary(key, password);

                if (!fromCache && utils.IsSessionStorageSupported()) {
                    if (!euSignTest.storePrivateKey(
                            keyName, key, password, certificates)) {
                        euSignTest.removeStoredPrivateKey();
                    }
                }

                euSignTest.privateKeyReaded(true);
                setKeyStatus('Ключ успішно завантажено', 'success')

                euSignTest.showOwnerInfo();
            } catch (e) {
                _onError(e);
            }
        },
        readPrivateKeyAsImage: function (file, onSuccess, onError) {
            var image = new Image();
            image.onload = function () {
                try {
                    var qr = new QRCodeDecode();

                    var canvas = document.createElement('canvas');
                    var context = canvas.getContext('2d');

                    canvas.width = image.width;
                    canvas.height = image.height;

                    context.drawImage(image, 0, 0, canvas.width, canvas.height);
                    var imagedata = context.getImageData(0, 0, canvas.width, canvas.height);
                    var decoded = qr.decodeImageData(imagedata, canvas.width, canvas.height);
                    onSuccess(file.name, StringToArray(decoded));
                } catch (e) {
                    console.log(e);
                    onError();
                }
            }

            image.src = utils.CreateObjectURL(file);
        },
        readPrivateKeyAsStoredFile: function () {
            var keyName = utils.GetSessionStorageItem(
                euSignTest.PrivateKeyNameSessionStorageName, false, false);
            var key = utils.GetSessionStorageItem(
                euSignTest.PrivateKeySessionStorageName, true, false);
            var password = utils.GetSessionStorageItem(
                euSignTest.PrivateKeyPasswordSessionStorageName, false, true);
            if (keyName == null || key == null || password == null)
                return;

            euSignTest.loadCAServer();

            setStatus('Зчитування ключа');
            euSignTest.uiPkFileName.value = keyName;
            euSignTest.uiPkPassword.value = password;
            var _readPK = function () {
                euSignTest.readPrivateKey(keyName, key, password, null, true);
            }
            setTimeout(_readPK, 10);

            return;
        },
        readPrivateKeyButtonClick: function () {
            var passwordTextField = euSignTest.uiPkPassword;
            var certificatesFiles = euSignTest.privateKeyCerts;

            var _onError = function (e) {
                setKeyStatus(e, 'error');
            };

            var _onSuccess = function (keyName, key) {
                euSignTest.readPrivateKey(keyName, new Uint8Array(key),
                    passwordTextField.value, null, false);
            }

            try {
                if (euSignTest.uiPkReadBtn.innerText == 'Зчитати') {
                    setStatus('Зчитування ключа');
                    setKeyStatus('Зчитування ключа, зачекайте...', 'info');
                    var files = euSignTest.uiPkFileInput.files;

                    if (files.length != 1) {
                        _onError("Виникла помилка при зчитуванні особистого ключа. " +
                            "Опис помилки: файл з особистим ключем не обрано");
                        return;
                    }
                    if (passwordTextField.value == "") {
                        passwordTextField.focus();
                        _onError("Виникла помилка при зчитуванні особистого ключа. " +
                            "Опис помилки: не вказано пароль доступу до особистого ключа");
                        return;
                    }

                    if (euSignTest.loadPKCertsFromFile &&
                        (certificatesFiles == null ||
                        certificatesFiles.length <= 0)) {
                        _onError("Виникла помилка при зчитуванні особистого ключа. " +
                            "Опис помилки: не обрано жодного сертифіката відкритого ключа");
                        return;
                    }

                    if (utils.IsFileImage(files[0])) {
                        euSignTest.readPrivateKeyAsImage(files[0], _onSuccess, _onError);
                    }
                    else {
                        var _onFileRead = function (readedFile) {
                            _onSuccess(readedFile.file.name, readedFile.data);
                        };
                        euSign.ReadFile(files[0], _onFileRead, _onError);
                    }
                } else {
                    euSignTest.removeStoredPrivateKey();
                    euSign.ResetPrivateKey();
                    euSignTest.privateKeyReaded(false);
                    passwordTextField.value = "";
                    euSignTest.clearPrivateKeyCertificatesList();
                    setKeyStatus('Завантажте ключ', 'info');
                    euSignTest.uiCertInfo.style.display = 'none';
                    euSignTest.uiSignBtn.disabled = 'disabled';
                }
            } catch (e) {
                _onError(e);
            }
        },
        showOwnerInfo: function () {
            try {
                var ownerInfo = euSign.GetPrivateKeyOwnerInfo();

                var infoStr = "Власник: <b>" + ownerInfo.GetSubjCN() + "</b><br/>" +
                    "ЦСК: <b>" + ownerInfo.GetIssuerCN() + "</b><br/>" +
                    "Серійний номер: <b>" + ownerInfo.GetSerial() + "</b>";
                euSignTest.uiCertInfo.innerHTML = infoStr;
                euSignTest.uiCertInfo.style.display = '';
                euSignTest.uiSignBtn.disabled = '';

            } catch (e) {
                console.log(e);
            }
        },
//-----------------------------------------------------------------------------
        signData: function () {
            // todo точка получения данных для подписи, local_data.obj - подписуемый объект json
            var data = prepareObject(local_data.obj);
            var isInternalSign = true; // включаем в подпись данные
            var isAddCert = true; // включаем в подпись сертификат
            var isSignHash = false;
            var dsAlgType = 1; // ДСТУ=1, RSA=2

            var _signDataFunction = function () {
                try {
                    var sign = "";
                    if (dsAlgType == 1) {
                        if (isInternalSign) {
                            sign = euSign.SignDataInternal(isAddCert, data, true);
                        } else {
                            if (isSignHash) {
                                var hash = euSign.HashData(data);
                                sign = euSign.SignHash(hash, true);
                            } else {
                                sign = euSign.SignData(data, true);
                            }
                        }
                    } else {
                        sign = euSign.SignDataRSA(data, isAddCert, !isInternalSign, true);
                    }
                    setStatus('');
                    setKeyStatus('Підпису успішно накладено. Триває вставка в ЦБД .... ', 'info');
                    euSignTest.uiVerifyBtn.disabled = false;
                    local_data.sign = sign;

                    /* todo вставка в ЦБД документа з подписью sign
                     POST/PUT api/0/tenders/xxx/documents?acc_token=yyy
                     attach file filename: "sign.p7s", contentType: "application/pkcs7-signature" */
                } catch (e) {
                    setStatus('');
                    setKeyStatus(e, 'error');
                }
            };

            setStatus('підпис данних');
            setTimeout(_signDataFunction, 10);
        },
        verifyData: function () {
            // todo тут нужно передать содержимое файла с подписью, вычитать по url из documents c {format: "application/pkcs7-signature", title: "sign.p7s"})
            var signedData = local_data.sign;
            euSignTest.uiVerifyErrorInfo.style.display = 'none';
            euSignTest.uiVerifySuccessInfo.style.display = 'none';
            var isInternalSign = true;
            var isSignHash = false;
            var isGetSignerInfo = true;

            var _verifyDataFunction = function () {
                try {
                    var info = "";
                    if (isInternalSign) {
                        info = euSign.VerifyDataInternal(signedData);
                    } else {
                        if (isSignHash) {
                            var hash = euSign.HashData(data);
                            info = euSign.VerifyHash(hash, signedData);
                        } else {
                            info = euSign.VerifyData(data, signedData);
                        }
                    }
                    if (isGetSignerInfo) {
                        var ownerInfo = info.GetOwnerInfo();
                        var timeInfo = info.GetTimeInfo();

                        var infoStr = "Підписувач:  <b>" + ownerInfo.GetSubjCN() + "</b><br/>" +
                            "ЦСК:  <b>" + ownerInfo.GetIssuerCN() + "</b><br/>" +
                            "Серійний номер:  <b>" + ownerInfo.GetSerial() + "</b><br/>";
                        euSignTest.uiCertInfo.innerHTML = infoStr;
                        euSignTest.uiCertInfo.style.display = '';

                        var timeMark = '';
                        if (timeInfo.IsTimeAvail()) {
                            timeMark = (timeInfo.IsTimeStamp() ?
                                    "Мітка часу:" : "Час підпису: <b>") + timeInfo.GetTime() + "</b>";
                        } else {
                            timeMark = "Час підпису відсутній";
                        }

                        if (isInternalSign) {
                            var signData = euSign.ArrayToString(info.GetData());
                            var currData = prepareObject(local_data.obj);
                            // todo remove
                            if (document.getElementById('cbTestError').checked) // для демострации неверной подписи
                                currData = prepareObject(local_data.obj2);
                            jsondiffpatch.formatters.html.hideUnchanged();
                            var delta = jsondiffpatch.diff(JSON.parse(signData), JSON.parse(currData));
                            if (!delta) {
                                var message = "Підпис успішно перевірено<br/>" + timeMark;
                                euSignTest.uiVerifySuccessInfo.innerHTML = message;
                                euSignTest.uiVerifySuccessInfo.style.display = '';
                            }
                            else {
                                euSignTest.uiVerifyDiffInfo.innerHTML = jsondiffpatch.formatters.html.format(delta, JSON.parse(currData));
                                euSignTest.uiVerifyErrorInfo.style.display = '';
                            }
                        }
                    }
                    setStatus('');
                } catch (e) {
                    console.log(e);
                    setStatus('');
                    euSignTest.uiVerifyErrorInfo.innerHTML = JSON.stringify(e);
                    euSignTest.uiVerifyErrorInfo.style.display = '';
                }
            }

            setStatus('перевірка підпису даних');
            setTimeout(_verifyDataFunction, 10);
        },
//-----------------------------------------------------------------------------
        chooseFileToSign: function (event) {
            var enable = (event.target.files.length == 1);

            //setPointerEvents(document.getElementById('SignFileButton'), enable);
        },
        chooseFileToVerify: function (event) {
            var enable = (document.getElementById('FileToVerify').files.length == 1) &&
                (document.getElementById("InternalSignCheckbox").checked ||
                document.getElementById('FileWithSign').files.length == 1)

            //setPointerEvents(document.getElementById('VerifyFileButton'), enable);
        },
        signFile: function () {
            var file = document.getElementById('FileToSign').files[0];

            if (file.size > Module.MAX_DATA_SIZE) {
                alert("Розмір файлу для піпису занадто великий. Оберіть файл меншого розміру");
                return;
            }

            var fileReader = new FileReader();

            fileReader.onloadend = (function (fileName) {
                return function (evt) {
                    if (evt.target.readyState != FileReader.DONE)
                        return;

                    var isInternalSign =
                        document.getElementById("InternalSignCheckbox").checked;
                    var isAddCert = document.getElementById(
                        "AddCertToInternalSignCheckbox").checked;
                    var dsAlgType = parseInt(
                        document.getElementById("DSAlgTypeSelect").value);

                    var data = new Uint8Array(evt.target.result);

                    try {
                        var sign;

                        if (dsAlgType == 1) {
                            if (isInternalSign)
                                sign = euSign.SignDataInternal(isAddCert, data, false);
                            else
                                sign = euSign.SignData(data, false);
                        } else {
                            sign = euSign.SignDataRSA(data, isAddCert,
                                !isInternalSign, false);
                        }

                        saveFile(fileName + ".p7s", sign);

                        setStatus('');
                        alert("Файл успішно підписано");
                    } catch (e) {
                        setStatus('');
                        alert(e);
                    }
                };
            })(file.name);

            setStatus('підпис файлу');
            fileReader.readAsArrayBuffer(file);
        },
        verifyFile: function () {
            var isInternalSign =
                document.getElementById("InternalSignCheckbox").checked;
            var isGetSignerInfo =
                document.getElementById("GetSignInfoCheckbox").checked;
            var files = [];

            files.push(document.getElementById('FileToVerify').files[0]);
            if (!isInternalSign)
                files.push(document.getElementById('FileWithSign').files[0]);

            if ((files[0].size > (Module.MAX_DATA_SIZE + EU_MAX_P7S_CONTAINER_SIZE)) ||
                (!isInternalSign && (files[1].size > Module.MAX_DATA_SIZE))) {
                alert("Розмір файлу для перевірки підпису занадто великий. Оберіть файл меншого розміру");
                return;
            }

            var _onSuccess = function (files) {
                try {
                    var info = "";
                    if (isInternalSign) {
                        info = euSign.VerifyDataInternal(files[0].data);
                    } else {
                        info = euSign.VerifyData(files[0].data, files[1].data);
                    }

                    var message = "Підпис успішно перевірено";

                    if (isGetSignerInfo) {
                        var ownerInfo = info.GetOwnerInfo();
                        var timeInfo = info.GetTimeInfo();

                        message += "\n";
                        message += "Підписувач: " + ownerInfo.GetSubjCN() + "\n" +
                            "ЦСК: " + ownerInfo.GetIssuerCN() + "\n" +
                            "Серійний номер: " + ownerInfo.GetSerial() + "\n";
                        if (timeInfo.IsTimeAvail()) {
                            message += (timeInfo.IsTimeStamp() ?
                                    "Мітка часу:" : "Час підпису: ") + timeInfo.GetTime();
                        } else {
                            message += "Час підпису відсутній";
                        }
                    }

                    if (isInternalSign) {
                        saveFile(files[0].name.substring(0,
                            files[0].name.length - 4), info.GetData());
                    }

                    alert(message);
                    setStatus('');
                } catch (e) {
                    alert(e);
                    setStatus('');
                }
            }

            var _onFail = function (files) {
                setStatus('');
                alert("Виникла помилка при зчитуванні файлів для перевірки підпису");
            }

            setStatus('перевірка підпису файлів');
            utils.LoadFilesToArray(files, _onSuccess, _onFail);
        },
//-----------------------------------------------------------------------------
        envelopData: function () {
            var issuers = euSignTest.recepientsCertsIssuers;
            var serials = euSignTest.recepientsCertsSerials;

            if (issuers == null || serials == null ||
                issuers.length <= 0 || serials.length <= 0) {
                alert("Не обрано жодного сертифіката отримувача");
                return;
            }

            var isAddSign = document.getElementById("AddSignCheckbox").checked;
            var data = document.getElementById("DataToEnvelopTextEdit").value;
            var envelopedText = document.getElementById("EnvelopedDataText");
            var developedText = document.getElementById("DevelopedDataText");
            var kepAlgType = parseInt(document.getElementById("KEPAlgTypeSelect").value);

            envelopedText.value = "";
            developedText.value = "";

            var _envelopDataFunction = function () {
                try {
                    if (kepAlgType == 1) {
                        envelopedText.value = euSign.EnvelopDataEx(
                            issuers, serials, isAddSign, data, true);
                    } else {
                        envelopedText.value = euSign.EnvelopDataRSAEx(
                            kepAlgType, issuers, serials, isAddSign, data, true);
                    }
                    setStatus('');
                } catch (e) {
                    setStatus('');
                    alert(e);
                }
            };

            setStatus('зашифрування даних');
            setTimeout(_envelopDataFunction, 10);
        },
        developData: function () {
            var envelopedText = document.getElementById("EnvelopedDataText");
            var developedText = document.getElementById("DevelopedDataText");

            developedText.value = "";

            var _developDataFunction = function () {
                try {
                    var info = euSign.DevelopData(envelopedText.value);
                    var ownerInfo = info.GetOwnerInfo();
                    var timeInfo = info.GetTimeInfo();

                    var message = "Дані успішно розшифровано";
                    message += "\n";
                    message += "Відправник: " + ownerInfo.GetSubjCN() + "\n" +
                        "ЦСК: " + ownerInfo.GetIssuerCN() + "\n" +
                        "Серійний номер: " + ownerInfo.GetSerial() + "\n";
                    if (timeInfo.IsTimeAvail()) {
                        message += (timeInfo.IsTimeStamp() ?
                                "Мітка часу:" : "Час підпису: ") + timeInfo.GetTime();
                    } else {
                        message += "Підпис відсутній";
                    }

                    developedText.value = euSign.ArrayToString(info.GetData());

                    setStatus('');
                    alert(message);
                } catch (e) {
                    setStatus('');
                    alert(e);
                }
            };

            setStatus('розшифрування даних');
            setTimeout(_developDataFunction, 10);
        },
//-----------------------------------------------------------------------------
        chooseEnvelopFile: function (event) {
            var enable = (event.target.files.length == 1);

            // setPointerEvents(document.getElementById('EnvelopFileButton'), enable);
            // setPointerEvents(document.getElementById('DevelopedFileButton'), enable);
        },
        envelopFile: function () {
            var issuers = euSignTest.recepientsCertsIssuers;
            var serials = euSignTest.recepientsCertsSerials;

            if (issuers == null || serials == null ||
                issuers.length <= 0 || serials.length <= 0) {
                alert("Не обрано жодного сертифіката отримувача");
                return;
            }

            var file = document.getElementById('EnvelopFiles').files[0];
            var fileReader = new FileReader();

            fileReader.onloadend = (function (fileName) {
                return function (evt) {
                    if (evt.target.readyState != FileReader.DONE)
                        return;

                    var fileData = new Uint8Array(evt.target.result);
                    var isAddSign = document.getElementById("AddSignCheckbox").checked;
                    var kepAlgType = parseInt(document.getElementById("KEPAlgTypeSelect").value);
                    var envelopedFileData;
                    try {
                        if (kepAlgType == 1) {
                            envelopedFileData = euSign.EnvelopDataEx(
                                issuers, serials, isAddSign, fileData, false);
                        } else {
                            envelopedFileData = euSign.EnvelopDataRSAEx(
                                kepAlgType, issuers, serials, isAddSign, fileData, false);
                        }
                        saveFile(fileName + ".p7e", envelopedFileData);

                        setStatus('');
                        alert("Файл успішно зашифровано");
                    } catch (e) {
                        setStatus('');
                        alert(e);
                    }
                };
            })(file.name);

            fileReader.readAsArrayBuffer(file);
        },
        developFile: function () {
            var file = document.getElementById('EnvelopFiles').files[0];
            var fileReader = new FileReader();

            if (file.size > (Module.MAX_DATA_SIZE + EU_MAX_P7E_CONTAINER_SIZE)) {
                alert("Розмір файлу для розшифрування занадто великий. Оберіть файл меншого розміру");
                return;
            }

            fileReader.onloadend = (function (fileName) {
                return function (evt) {
                    if (evt.target.readyState != FileReader.DONE)
                        return;

                    var fileData = new Uint8Array(evt.target.result);

                    try {
                        var info = euSign.DevelopData(fileData);
                        var ownerInfo = info.GetOwnerInfo();
                        var timeInfo = info.GetTimeInfo();

                        var message = "Файл успішно розшифровано";
                        message += "\n";
                        message += "Відправник: " + ownerInfo.GetSubjCN() + "\n" +
                            "ЦСК: " + ownerInfo.GetIssuerCN() + "\n" +
                            "Серійний номер: " + ownerInfo.GetSerial() + "\n";
                        if (timeInfo.IsTimeAvail()) {
                            message += (timeInfo.IsTimeStamp() ?
                                    "Мітка часу:" : "Час підпису: ") + timeInfo.GetTime();
                        } else {
                            message += "Підпис відсутній";
                        }

                        setStatus('');
                        alert(message);

                        saveFile(fileName.substring(0, fileName.length - 4), info.GetData());
                    } catch (e) {
                        setStatus('');
                        alert(e);
                    }
                };
            })(file.name);

            setStatus('розшифрування файлу');
            fileReader.readAsArrayBuffer(file);
        },
//-----------------------------------------------------------------------------
        getOwnCertificateInfo: function (keyType, keyUsage) {
            try {
                var index = 0;
                while (true) {
                    var info = euSign.EnumOwnCertificates(index);
                    if (info == null)
                        return null;

                    if ((info.GetPublicKeyType() == keyType) &&
                        ((info.GetKeyUsageType() & keyUsage) == keyUsage)) {
                        return info;
                    }

                    index++;
                }
            } catch (e) {
                alert(e);
            }

            return null;
        },
        getOwnCertificate: function (keyType, keyUsage) {
            try {
                var info = euSignTest.getOwnCertificateInfo(
                    keyType, keyUsage);
                if (info == null)
                    return null;

                return euSign.GetCertificate(
                    info.GetIssuer(), info.GetSerial());
            } catch (e) {
                alert(e);
            }

            return null;
        },
//-----------------------------------------------------------------------------
        privateKeyReaded: function (isReaded) {
            var enabled = '';
            var disabled = 'disabled';

            if (!isReaded) {
                enabled = 'disabled';
                disabled = '';
            }
            setStatus('');

            euSignTest.uiCaServersSelect.disabled = disabled;
            euSignTest.uiPkSelectBtn.disabled = disabled;
            euSignTest.uiPkFileName.disabled = disabled;
            euSignTest.uiPkCertsDiv.hidden = (!isReaded && euSignTest.loadPKCertsFromFile) ? '' : 'hidden';
            euSignTest.uiPkReadBtn.title = isReaded ? 'Зтерти' : 'Зчитати';
            euSignTest.uiPkReadBtn.innerHTML = isReaded ? 'Зтерти' : 'Зчитати';

            euSignTest.uiPkPassword.disabled = disabled;
            if (!isReaded) {
                euSignTest.uiPkPassword.value = '';
                euSignTest.uiPkFileName.value = '';
                euSignTest.uiPkFileInput.value = null;
            }
        },
        setSelectPKCertificatesEvents: function () {
            euSignTest.uiCertFileInput.addEventListener(
                'change', function (evt) {
                    if (evt.target.files.length <= 0) {
                        euSignTest.clearPrivateKeyCertificatesList();
                    } else {
                        euSignTest.privateKeyCerts = evt.target.files;
                        euSignTest.setFileItemsToList(euSignTest.uiCertList.id, evt.target.files);
                    }
                }, false);
        },
        clearPrivateKeyCertificatesList: function () {
            euSignTest.privateKeyCerts = null;
            euSignTest.uiCertFileInput.value = null;
            euSignTest.uiCertList.innerHTML = "Сертифікати відкритого ключа не обрано" + '<br>';
        },
        setItemsToList: function (listId, items) {
            var output = [];
            for (var i = 0, item; item = items[i]; i++) {
                output.push('<li><strong>', item, '</strong></li>');
            }
            document.getElementById(listId).innerHTML = '<ul>' + output.join('') + '</ul>';
        },
        setFileItemsToList: function (listId, items) {
            var output = [];
            for (var i = 0, item; item = items[i]; i++) {
                output.push('<li><strong>', item.name, '</strong></li>');
            }

            document.getElementById(listId).innerHTML =
                '<ul>' + output.join('') + '</ul>';
        }
    });

//=============================================================================

var euSignTest = EUSignCPTest();
var euSign = EUSignCP();
var utils = Utils(euSign);

//=============================================================================

function setStatus(message) {
    if (message != '')
        message = '(' + message + '...)';
    document.getElementById('status').innerHTML = message;
}

function setKeyStatus(message, type) {
    euSignTest.uiPkStatusInfo.innerHTML = message;
    switch (type) {
        case 'error' :
            document.getElementById('keyStatusPanel').className = 'panel panel-danger';
            break;
        case 'info' :
            document.getElementById('keyStatusPanel').className = 'panel panel-info';
            break;
        case 'success' :
            document.getElementById('keyStatusPanel').className = 'panel panel-success';
            break;
    }
}

function saveFile(fileName, array) {
    var blob = new Blob([array], {type: "application/octet-stream"});
    saveAs(blob, fileName);
}

function pageLoaded() {
    euSignTest.uiPkFileInput.addEventListener('change', euSignTest.selectPrivateKeyFile, false);
}

// init call after initialize euscp.js
function EUSignCPModuleInitialized(isInitialized) {
    if (isInitialized)
        euSignTest.initialize();
    else
        setKeyStatus("Криптографічну бібліотеку не ініціалізовано", 'error');
}

//=============================================================================

pageLoaded();