
local my_proto = Proto("my_proto","My Proto")
local data_dis = Dissector.get("data") -- The traditional data dissector 

-- Proto Fields 
my_proto.fields = {}
local f = my_proto.fields
f.header = ProtoField.uint8("my_proto.header","Data Header",base.HEX)
f.req = ProtoField.uint8("my_proto.req","Req/Res",base.HEX,{[0]='Request',[1]='Response'},0x80)
f.adr = ProtoField.uint8("my_proto.req","Address",base.HEX,nil,0x7F)
f.value = ProtoField.uint16("my_proto.value","Value",base.DEC)
f.seq = ProtoField.uint8("my_proto.seq","Sequence",base.DEC)
f.len = ProtoField.uint8("my_proto.len","Length",base.DEC)
f.data = ProtoField.bytes("my_proto.data","Data")
-- Dissector Function
function my_proto.dissector(buf,pinfo,tree)
	local info_str = ''
	local subtree = tree:add(my_proto,buf(0), "My Proto" )
	local offset = 0 
	local header_sub = subtree:add(f.header,buf(offset,1))
	header_sub:add(f.req,buf(offset,1))
	header_sub:add(f.adr,buf(offset,1))
	info_str = info_str .. 'ADR:' .. bit.band(buf(0,1):uint(), 0x7F) .. ', '
	offset = offset + 1
	
	subtree:add(f.seq,buf(offset,1))
	info_str = info_str .. 'Seq[' .. buf(1,1):uint() .. '], '
	offset = offset + 1
	
	if bit.band(buf(0,1):uint(), 0x80) > 0 then 
		info_str = 'Req, ' .. info_str  
	else
		info_str = 'Res, ' .. info_str  
		subtree:add(f.value,buf(offset,2))
		info_str = info_str .. 'Data: ' .. buf(offset,2):uint() 
		offset = offset + 2
		
		subtree:add(f.len,buf(offset,1))
		offset = offset + 1
		subtree:add(f.data,buf(offset,buf:len() - offset))
		data_dis:call(buf:range(offset):tvb(),pinfo,tree)
	end 
	
	pinfo.cols.protocol = 'My Proto'
	pinfo.cols.info = info_str
end

wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, my_proto)
