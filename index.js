let arraySign = {}

function onChange(event) { 
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

  arraySign.pin = document.getElementById("pin").value;
  console.log(arraySign);
    $.ajax({
        type: 'POST',
        url: 'https://Felipe:5000/sign',
        //url: 'https://Dinamo:5696/kmip',
        contentType:"application/json; charset=utf-8",
        dataType: 'json',
        data: JSON.stringify(arraySign),
        success: function(responseData, textStatus, jqXHR) 
        {
            console.log(responseData);
        },
        error: function (responseData, textStatus, errorThrown) 
        {
            console.warn(responseData, textStatus, errorThrown);
        }
    });
}