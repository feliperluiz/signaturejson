let hashDocumento;

function onChange(event) { 
    var logFile = $('#input_file').get(0).files[0];
    var readerFile = new FileReader();
    readerFile.readAsBinaryString(logFile);
    readerFile.onload = function(event){
        var arrayBuffer = event.target.result;
        hashDocumento = CryptoJS.SHA256(arrayBuffer).toString(CryptoJS.enc.Hex);
        console.log(hashDocumento);
             
    }
}
//cd c:/Users/Felipe/Desktop/TCC/Signature/reporter
function Sign () {  

  event.preventDefault();

    $.ajax({
        type: 'POST',
        url: 'http://localhost:5000/sign',
        data: hashDocumento,
        success: function(responseData, textStatus, jqXHR) 
        {
            console.log(responseData);
        },
        error: function (responseData, textStatus, errorThrown) 
        {
            console.warn(responseData, textStatus, errorThrown);
            alert('failed - ' + textStatus);
        }
    });
}