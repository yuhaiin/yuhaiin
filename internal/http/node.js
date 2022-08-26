function latency(id) {
    const test = document.querySelector('#i' + id + ' .test');

    test.innerText = "Testing...";

    var tcp = false;
    var udp = false;
    var updateTestText = () => { if (tcp && udp) test.innerText = "Test"; };

    lat(id, "tcp", () => {
        tcp = true;
        updateTestText();
    });
    lat(id, "udp", () => {
        udp = true;
        updateTestText();
    });
}

function nodeSelectOrDetail(hash) {
    const i = document.querySelector('input[name=select_node][value="' + hash + '"]')
    if (i.checked === true) window.location = "/node?hash=" + encodeURIComponent(hash)
    else i.click()
}

function lat(id, type, callback) {
    const elem = document.querySelector('#i' + id + ' .' + type);

    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/latency?hash=" + id + "&type=" + type, true);
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState != 4) return;
        let latency = null;
        if (xmlhttp.status == 200) {
            latency = xmlhttp.responseText;
            console.log('get ' + type + ' data：', latency);
        }

        elem.innerText = latency != "" ? latency : "9999.99ms";
        callback();
    }
    xmlhttp.send();
}

function del() {
    var hash = getSelectNode();
    console.log('del node:', hash);
    if (hash == null) return;
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("DELETE", "/node?hash=" + hash, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState != 4) return;
        location.reload();
    }
}

function use(net) {
    var hash = getSelectNode();
    console.log('use node:', hash);
    if (hash == null) return;

    useByHash(net, hash);
}

function useByHash(net, hash) {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("PUT", "/node?hash=" + hash + "&net=" + net, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState != 4) return;
        if (xmlhttp.status == 200) window.location = "/node?hash=" + hash;
    }
}

function getSelectNode() {
    return document.querySelector('input[name=select_node]:checked').value;
}