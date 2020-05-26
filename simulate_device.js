/**
 * @file simulate_devices.js
 * @author NZ
 * @license MIT
 * @description Streams a simple Request/Response protocol into wireshark 
 */

// Choose the link layer for pcap data, 148 is reserved for users: https://www.tcpdump.org/linktypes.html 
var link_type = 148;

// Create .pcap header 
function get_header(link_layer_type){
    var pcap_header = [];

    // Magic number, defines endian-ess 
    var magic_number = [0xa1,0xb2,0xc3,0xd4];

    // Pcap verison major
    var version_major = [0x0,0x2];

    // Version minor 
    var version_minor = [0x0,0x4];
    var this_zone = [0x0,0x0,0x0,0x0];
    var sig_figs = [0x0,0x0,0x0,0x0];
    var snapshot_length = [0,0,0,128];
    var link_type = [0,0,0,link_layer_type];

    pcap_header = pcap_header.concat(magic_number,version_major,version_minor,this_zone,sig_figs,snapshot_length,link_type);

    return pcap_header;
}

// Convert uint32t to bytes, a bit painful in js 
function u32_2a (num){
    return Array.prototype.slice.call(new Uint8Array(Uint32Array.from([num]).buffer)).reverse();
}

function u16_2a(num){
    return Array.prototype.slice.call(new Uint8Array(Uint16Array.from([num]).buffer)).reverse();
}

// Gets a single .pcap packet timestamping with date.now()
function get_packet (payload){
    var arr = [];
    var time_now = Date.now();
    var time_s = Math.floor(time_now/1000);
    var time_us = Math.floor((time_now%1000)*1000);

    arr = arr.concat(u32_2a(time_s)); // Time s 
    arr = arr.concat(u32_2a(time_us)); // Time us
    arr = arr.concat(u32_2a(payload.length)); // Include length
    arr = arr.concat(u32_2a(payload.length)); // Origin Length 
    arr = arr.concat(payload);
    return arr;
}

var counter = 0;

function send_header(){
    var header = get_header(link_type);
    process.stdout.write(Uint8Array.from(header));
}
send_header();

var seq = 0;

// Request Packet Example
function req_packet(){
    var send_buf = [];
    var adr = 0x15; 
    var byte0 = (0x1<<7) | adr;
    send_buf.push(byte0);
    seq = (++seq) %255;
    send_buf.push(seq);
    var packet_arr = get_packet(send_buf.flat().flat());
    process.stdout.write(Uint8Array.from(packet_arr));
}

// Response Packet Example 
function res_packet(){
    var send_buf = [];
    var adr = 0x15;
    send_buf.push(adr);
    send_buf.push(seq);
    var data = Math.floor(Math.random()*50+50);
    send_buf.push(0x0,data);

    var len = Math.floor(Math.random()*50);
    send_buf.push(len);
    for(var i = 0; i < len; i++ ){
        send_buf.push(Math.round(Math.random()*255));
    }

    var packet_arr = get_packet(send_buf.flat().flat());
    process.stdout.write(Uint8Array.from(packet_arr));
}

// Generate data every 2.5s
setInterval(()=>{
    req_packet();
    res_packet();
    counter++;
},2500);
