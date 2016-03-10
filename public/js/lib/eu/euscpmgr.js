//=============================================================================

var URL_GET_CERTIFICATES = "/data/CACertificates.p7b?version=1.0.5";
var URL_CAS = "/data/CAs.json?version=1.0.5";
var URL_XML_HTTP_PROXY_SERVICE = "https://vpn.unity-bars.com.ua:40103/proxy/ProxyHandler.ashx";

//=============================================================================

var EUSignCPMgr = NewClass({
        "Vendor": "JSC IIT",
        "ClassVersion": "1.0.0",
        "ClassName": "EUSignCPMgr",
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
        // ui elements euSignMgr.uiCertList
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
                        euSignMgr.setDefaultSettings();
                    }
                    euSignMgr.loadCertsFromServer();
                    euSignMgr.setCASettings(0);

                    euSignMgr.setSelectPKCertificatesEvents();
                    if (utils.IsSessionStorageSupported()) {
                        var _readPrivateKeyAsStoredFile = function () {
                            euSignMgr.readPrivateKeyAsStoredFile();
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

            euSignMgr.loadCAsSettings(_onSuccess, _onError);
        },
        loadCAsSettings: function (onSuccess, onError) {
            var pThis = this;

            var _onSuccess = function (casResponse) {
                try {
                    var servers = JSON.parse(casResponse.replace(/\\'/g, "'"));

                    var select = euSignMgr.uiCaServersSelect;
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
                euSignMgr.CACertificatesSessionStorageName, true, false);
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
                        euSignMgr.CACertificatesSessionStorageName,
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

                euSignMgr.CAServer = caServer;
                euSignMgr.offline = offline;
                euSignMgr.useCMP = useCMP;
                euSignMgr.loadPKCertsFromFile = loadPKCertsFromFile;

                var message = "Оберіть файл з особистим ключем (зазвичай з ім'ям Key-6.dat) та вкажіть пароль захисту";
                if (loadPKCertsFromFile) {
                    message += ", а також оберіть сертифікат(и) (зазвичай, з розширенням cer, crt)";
                }
                setKeyStatus(message, 'info');
                var settings;

                euSignMgr.uiPkCertsDiv.hidden = loadPKCertsFromFile ? '' : 'hidden';
                euSignMgr.clearPrivateKeyCertificatesList();

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
            var index = euSignMgr.uiCaServersSelect.selectedIndex;

            if (index < euSignMgr.CAsServers.length)
                return euSignMgr.CAsServers[index];

            return null;
        },
        loadCAServer: function () {
            var index = utils.GetSessionStorageItem(
                euSignMgr.CAServerIndexSessionStorageName, false, false);
            if (index != null) {
                euSignMgr.uiCaServersSelect.selectedIndex =
                    parseInt(index);
                euSignMgr.setCASettings(parseInt(index));
            }
        },
        storeCAServer: function () {
            var index = euSignMgr.uiCaServersSelect.selectedIndex;
            return utils.SetSessionStorageItem(
                euSignMgr.CAServerIndexSessionStorageName, index.toString(), false);
        },
        removeCAServer: function () {
            utils.RemoveSessionStorageItem(
                euSignMgr.CAServerIndexSessionStorageName);
        },
//-----------------------------------------------------------------------------
        storePrivateKey: function (keyName, key, password, certificates) {
            if (!utils.SetSessionStorageItem(
                    euSignMgr.PrivateKeyNameSessionStorageName, keyName, false) || !utils.SetSessionStorageItem(
                    euSignMgr.PrivateKeySessionStorageName, key, false) || !utils.SetSessionStorageItem(
                    euSignMgr.PrivateKeyPasswordSessionStorageName, password, true) || !euSignMgr.storeCAServer()) {
                return false;
            }

            if (Array.isArray(certificates)) {
                if (!utils.SetSessionStorageItems(
                        euSignMgr.PrivateKeyCertificatesSessionStorageName,
                        certificates, false)) {
                    return false;
                }
            } else {
                if (!utils.SetSessionStorageItem(
                        euSignMgr.PrivateKeyCertificatesChainSessionStorageName,
                        certificates, false)) {
                    return false;
                }
            }

            return true;
        },
        removeStoredPrivateKey: function () {
            utils.RemoveSessionStorageItem(
                euSignMgr.PrivateKeyNameSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignMgr.PrivateKeySessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignMgr.PrivateKeyPasswordSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignMgr.PrivateKeyCertificatesChainSessionStorageName);
            utils.RemoveSessionStorageItem(
                euSignMgr.PrivateKeyCertificatesSessionStorageName);

            euSignMgr.removeCAServer();
        },
//-----------------------------------------------------------------------------
        selectPrivateKeyFile: function (event) {
            var enable = (event.target.files.length == 1);
            euSignMgr.uiPkReadBtn.disabled = enable ? '' : 'disabled';
            euSignMgr.uiPkPassword.disabled = enable ? '' : 'disabled';
            euSignMgr.uiPkFileName.value = enable ? event.target.files[0].name : '';
            euSignMgr.uiPkPassword.value = '';
        },
//-----------------------------------------------------------------------------
        getPrivateKeyCertificatesByCMP: function (key, password, onSuccess, onError) {
            try {
                var cmpAddress = euSignMgr.getCAServer().cmpAddress + ":80";
                var keyInfo = euSign.GetKeyInfoBinary(key, password);

                onSuccess(euSign.GetCertificatesByKeyInfo(keyInfo, [cmpAddress]));
            } catch (e) {
                onError(e);
            }
        },
        getPrivateKeyCertificates: function (key, password, fromCache, onSuccess, onError) {
            var certificates;
            if (euSignMgr.CAServer != null &&
                euSignMgr.CAServer.certsInKey) {
                onSuccess([]);
                return;
            }

            if (fromCache) {
                if (euSignMgr.useCMP) {
                    certificates = utils.GetSessionStorageItem(
                        euSignMgr.PrivateKeyCertificatesChainSessionStorageName, true, false);
                } else if (euSignMgr.loadPKCertsFromFile) {
                    certificates = utils.GetSessionStorageItems(
                        euSignMgr.PrivateKeyCertificatesSessionStorageName, true, false)
                }

                onSuccess(certificates);
            } else if (euSignMgr.useCMP) {
                euSignMgr.getPrivateKeyCertificatesByCMP(
                    key, password, onSuccess, onError);
            } else if (euSignMgr.loadPKCertsFromFile) {
                var _onSuccess = function (files) {
                    var certificates = [];
                    for (var i = 0; i < files.length; i++) {
                        certificates.push(files[i].data);
                    }

                    onSuccess(certificates);
                };
                euSign.ReadFiles(
                    euSignMgr.privateKeyCerts,
                    _onSuccess, onError);
            }
        },
        readPrivateKey: function (keyName, key, password, certificates, fromCache) {
            var _onError = function (e) {
                setStatus('');
                var message = (e.message + '(' + e.errorCode + ')') ? (e.message) : (e);
                setKeyStatus(message, 'error');

                if (fromCache) {
                    euSignMgr.removeStoredPrivateKey();
                    euSignMgr.privateKeyReaded(false);
                }
            };

            if (certificates == null) {
                var _onGetCertificates = function (certs) {
                    if (certs == null) {
                        _onError(euSign.MakeError(EU_ERROR_CERT_NOT_FOUND));
                        return;
                    }
                    euSignMgr.readPrivateKey(keyName, key, password, certs, fromCache);
                }

                euSignMgr.getPrivateKeyCertificates(key, password, fromCache, _onGetCertificates, _onError);
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
                    if (!euSignMgr.storePrivateKey(
                            keyName, key, password, certificates)) {
                        euSignMgr.removeStoredPrivateKey();
                    }
                }

                euSignMgr.privateKeyReaded(true);
                setKeyStatus('Ключ успішно завантажено', 'success')

                euSignMgr.showOwnerInfo();
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
                euSignMgr.PrivateKeyNameSessionStorageName, false, false);
            var key = utils.GetSessionStorageItem(
                euSignMgr.PrivateKeySessionStorageName, true, false);
            var password = utils.GetSessionStorageItem(
                euSignMgr.PrivateKeyPasswordSessionStorageName, false, true);
            if (keyName == null || key == null || password == null)
                return;

            euSignMgr.loadCAServer();

            setStatus('Зчитування ключа');
            euSignMgr.uiPkFileName.value = keyName;
            euSignMgr.uiPkPassword.value = password;
            var _readPK = function () {
                euSignMgr.readPrivateKey(keyName, key, password, null, true);
            }
            setTimeout(_readPK, 10);

            return;
        },
        readPrivateKeyButtonClick: function () {
            var passwordTextField = euSignMgr.uiPkPassword;
            var certificatesFiles = euSignMgr.privateKeyCerts;

            var _onError = function (e) {
                setKeyStatus(e, 'error');
            };

            var _onSuccess = function (keyName, key) {
                euSignMgr.readPrivateKey(keyName, new Uint8Array(key),
                    passwordTextField.value, null, false);
            }

            try {
                console.log(euSignMgr.uiPkReadBtn.title);
                if (euSignMgr.uiPkReadBtn.title == 'Зчитати') {
                    setStatus('Зчитування ключа');
                    console.log(2);
                    setKeyStatus('Зчитування ключа, зачекайте...', 'info');
                    console.log(3);
                    var files = euSignMgr.uiPkFileInput.files;
                    console.log(files.length);
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

                    if (euSignMgr.loadPKCertsFromFile &&
                        (certificatesFiles == null ||
                        certificatesFiles.length <= 0)) {
                        _onError("Виникла помилка при зчитуванні особистого ключа. " +
                            "Опис помилки: не обрано жодного сертифіката відкритого ключа");
                        return;
                    }

                    if (utils.IsFileImage(files[0])) {
                        euSignMgr.readPrivateKeyAsImage(files[0], _onSuccess, _onError);
                    }
                    else {
                        var _onFileRead = function (readedFile) {
                            _onSuccess(readedFile.file.name, readedFile.data);
                        };
                        euSign.ReadFile(files[0], _onFileRead, _onError);
                    }
                } else {
                    euSignMgr.removeStoredPrivateKey();
                    euSign.ResetPrivateKey();
                    euSignMgr.privateKeyReaded(false);
                    passwordTextField.value = "";
                    euSignMgr.clearPrivateKeyCertificatesList();
                    setKeyStatus('Завантажте ключ', 'info');
                    euSignMgr.uiCertInfo.style.display = 'none';
                    euSignMgr.uiSignBtn.disabled = 'disabled';
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
                euSignMgr.uiCertInfo.innerHTML = infoStr;
                euSignMgr.uiCertInfo.style.display = '';
                euSignMgr.uiSignBtn.disabled = '';

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
                    euSignMgr.uiVerifyBtn.disabled = false;
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
        verifyData: function (use_test_data) {
            // todo тут нужно передать содержимое файла с подписью, вычитать по url из documents c {format: "application/pkcs7-signature", title: "sign.p7s"})
            var signedData = local_data.sign;
            if(use_test_data)
                signedData = local_data.test_sign;
            euSignMgr.uiVerifyErrorInfo.style.display = 'none';
            euSignMgr.uiVerifySuccessInfo.style.display = 'none';
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
                        euSignMgr.uiCertInfo.innerHTML = infoStr;
                        euSignMgr.uiCertInfo.style.display = '';

                        var timeMark = '';
                        if (timeInfo.IsTimeAvail()) {
                            timeMark = (timeInfo.IsTimeStamp() ?
                                    "Мітка часу:" : "Час підпису: <b>") + timeInfo.GetTime() + "</b>";
                        } else {
                            timeMark = "Час підпису відсутній";
                        }

                        if (isInternalSign) {
                            var signData = prepareObject(JSON.parse(euSign.ArrayToString(info.GetData())));
                            var currData = prepareObject(local_data.obj);
                            // todo remove
                            if (document.getElementById('cbTestError').checked) // для демострации неверной подписи
                                currData = prepareObject(local_data.obj2);
                            if(use_test_data)
                                currData = prepareObject(local_data.test_data);

                            jsondiffpatch.formatters.html.hideUnchanged();
                            var delta = jsondiffpatch.diff(JSON.parse(signData), JSON.parse(currData));
                            if (!delta) {
                                var message = "Підпис успішно перевірено<br/>" + timeMark;
                                euSignMgr.uiVerifySuccessInfo.innerHTML = message;
                                euSignMgr.uiVerifySuccessInfo.style.display = '';
                            }
                            else {
                                euSignMgr.uiVerifyDiffInfo.innerHTML = jsondiffpatch.formatters.html.format(delta, JSON.parse(currData));
                                euSignMgr.uiVerifyErrorInfo.style.display = '';
                            }
                        }
                    }
                    setStatus('');
                } catch (e) {
                    console.log(e);
                    setStatus('');
                    euSignMgr.uiVerifyErrorInfo.innerHTML = JSON.stringify(e);
                    euSignMgr.uiVerifyErrorInfo.style.display = '';
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
            var issuers = euSignMgr.recepientsCertsIssuers;
            var serials = euSignMgr.recepientsCertsSerials;

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
            var issuers = euSignMgr.recepientsCertsIssuers;
            var serials = euSignMgr.recepientsCertsSerials;

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
                var info = euSignMgr.getOwnCertificateInfo(
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

            euSignMgr.uiCaServersSelect.disabled = disabled;
            euSignMgr.uiPkSelectBtn.disabled = disabled;
            euSignMgr.uiPkFileName.disabled = disabled;
            euSignMgr.uiPkCertsDiv.hidden = (!isReaded && euSignMgr.loadPKCertsFromFile) ? '' : 'hidden';
            euSignMgr.uiPkReadBtn.title = isReaded ? 'Зтерти' : 'Зчитати';
            euSignMgr.uiPkReadBtn.innerHTML = isReaded ? 'Зтерти' : 'Зчитати';

            euSignMgr.uiPkPassword.disabled = disabled;
            if (!isReaded) {
                euSignMgr.uiPkPassword.value = '';
                euSignMgr.uiPkFileName.value = '';
                euSignMgr.uiPkFileInput.value = null;
            }
        },
        setSelectPKCertificatesEvents: function () {
            euSignMgr.uiCertFileInput.addEventListener(
                'change', function (evt) {
                    if (evt.target.files.length <= 0) {
                        euSignMgr.clearPrivateKeyCertificatesList();
                    } else {
                        euSignMgr.privateKeyCerts = evt.target.files;
                        euSignMgr.setFileItemsToList(euSignMgr.uiCertList.id, evt.target.files);
                    }
                }, false);
        },
        clearPrivateKeyCertificatesList: function () {
            euSignMgr.privateKeyCerts = null;
            euSignMgr.uiCertFileInput.value = null;
            euSignMgr.uiCertList.innerHTML = "Сертифікати відкритого ключа не обрано" + '<br>';
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

var euSignMgr = EUSignCPMgr();
var euSign = EUSignCP();
var utils = Utils(euSign);

//=============================================================================

function setStatus(message) {
    if (message != '')
        message = '(' + message + '...)';
    document.getElementById('status').innerHTML = message;
}

function setKeyStatus(message, type) {
    euSignMgr.uiPkStatusInfo.innerHTML = message;
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
    euSignMgr.uiPkFileInput.addEventListener('change', euSignMgr.selectPrivateKeyFile, false);
}

// init call after initialize euscp.js
function EUSignCPModuleInitialized(isInitialized) {
    if (isInitialized)
        euSignMgr.initialize();
    else
        setKeyStatus("Криптографічну бібліотеку не ініціалізовано", 'error');
}

//=============================================================================

pageLoaded();