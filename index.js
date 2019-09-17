let arraySign = {}
let signature = '';

function onChange(event) { 
    var time1 = new Date().getTime();
    var logFile = $('#input_file').get(0).files[0];
    var readerFile = new FileReader();
    readerFile.readAsBinaryString(logFile);
    readerFile.onload = function(event){
        var arrayBuffer = event.target.result;
        hashDocumento = CryptoJS.SHA256(arrayBuffer).toString(CryptoJS.enc.Hex);
        console.log(hashDocumento)
        arraySign.hash = hashDocumento;
    }
}
//cd c:/Users/Felipe/Desktop/TCC/Signature/reporter
function Sign () {  
  
  console.log(new Date() + " " + new Date().getMilliseconds())

  arraySign.pin = document.getElementById("pin").value;
    $.ajax({
        type: 'POST',
        url: 'https://Felipe:5000/sign',
        contentType: 'application/json; charset=utf-8',
        data: JSON.stringify(arraySign),
        success: function(responseData, textStatus, jqXHR) 
        {
            console.log(new Date() + " " + new Date().getMilliseconds())
            signature = responseData
            downloadFile(signature)
        },
        error: function (responseData, textStatus, errorThrown) 
        {
            console.warn(responseData, textStatus, errorThrown)
        }
    });
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