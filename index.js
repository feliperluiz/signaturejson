var arraySign = {}
var signature = '';

function onChange(event) { 
    var logFile = $('#input_file').get(0).files[0];
    var readerFile = new FileReader();
    readerFile.readAsBinaryString(logFile);
    readerFile.onload = function(event){
        var arrayBuffer = event.target.result;
        console.log(new Date().getHours() + ":" + new Date().getMinutes() + ":" + new Date().getSeconds() + ":" + new Date().getMilliseconds());
        hashDocumento = CryptoJS.SHA256(arrayBuffer).toString(CryptoJS.enc.Hex);
        console.log(new Date().getHours() + ":" + new Date().getMinutes() + ":" + new Date().getSeconds() + ":" + new Date().getMilliseconds());
        arraySign.hash = hashDocumento;
        console.log(arraySign)
    }
    
}
//cd c:/Users/Felipe/Desktop/TCC/signaturepython/reporter/teste_sign.py
function Sign () {  
  
  console.log(new Date().getHours() + ":" + new Date().getMinutes() + ":" + new Date().getSeconds() + ":" + new Date().getMilliseconds());

  arraySign.pin = document.getElementById("pin").value;

  var xmlhttp = new XMLHttpRequest();
  var theUrl = "https://Felipe:5000/sign";
  xmlhttp.open("POST", theUrl);
  xmlhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
  xmlhttp.onload = function(e) {
  if (this.status == 200) {
    var jsonParser = JSON.parse(this.response)
    isValid = jsonParser.valid;
    signature = jsonParser.signature;
    if (isValid) {
        $("#isValid").show();
    } else {
        $("#isInvalid").show();
    }
    console.log(new Date().getHours() + ":" + new Date().getMinutes() + ":" + new Date().getSeconds() + ":" + new Date().getMilliseconds());
    downloadFile(signature);
  } else {
    console.log(e);
  }
}
  xmlhttp.send(JSON.stringify(arraySign))
    //openssl req -config "C:\Program Files (x86)\GnuWin32\share\openssl.cnf" -nodes -x509 -newkey rsa:2048 -keyout keyfeliperluiz.pem -out certfeliperluiz.pem -days 365
}

function downloadFile(sign) {
    var obj = sign;
    var filename = "file.signature";
    var blob = new Blob([sign], {type: 'text/plain'});
    if (window.navigator && window.navigator.msSaveOrOpenBlob) {
        window.navigator.msSaveOrOpenBlob(blob, filename);
    } else{
        var e = document.createEvent('MouseEvents'),
        a = document.createElement('a');
        a.download = filename;
        a.href = window.URL.createObjectURL(blob);
        a.dataset.downloadurl = ['text/plain', a.download, a.href].join(':');
        e.initEvent('click', true, false, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
        a.dispatchEvent(e);
    }
}