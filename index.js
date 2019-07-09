var xhr = new XMLHttpRequest();
var url = "https://hsmlab63.dinamonetworks.com/api/gen_rand";
var dadoStr = '{"len": 16}'
xhr.open("POST", url, true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.setRequestHeader("Authorization", "HSM 48D50D8E79ABBEFC5F711B4B517046B29E4F7D52229E1587DB570752E13A081A");
xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
        var json = JSON.parse(xhr.responseText);
        console.log(json.email + ", " + json.password);
    }
};
var data = JSON.stringify({"len": 16});
xhr.send(data);