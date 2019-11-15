var arraySign = {}
var signature = '';

function onChange(event) { 
    var logFile = $('#input_file').get(0).files[0];
    var readerFile = new FileReader();
    readerFile.readAsBinaryString(logFile);
    readerFile.onload = function(event){
        var arrayBuffer = event.target.result;
        hashDocumento = CryptoJS.SHA256(arrayBuffer).toString(CryptoJS.enc.Hex);
        arraySign.hash = hashDocumento;
    }
}

function Sign () {
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
    downloadFile(signature);
  } else {
    console.log(e);
  }
}
  xmlhttp.send(JSON.stringify(arraySign))
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