#global _url: table[addr] of set[string];
type rec:record{
	t1:time;
	_count:count;
	_404count:count;
	_url:set[string];
	};

global tables:table[addr] of rec;
global t1:time=current_time();
global intvl:interval=10 min;
global ct:count=0;

event http_reply(c:connection; version:string; code:count; reason:string;)
	{
	if(c$id$orig_h in tables)
		{
		if( c$start_time - tables[c$id$orig_h]$t1 < intvl )
			{
			if(code == 404)
				{
				tables[c$id$orig_h]$_count=tables[c$id$orig_h]$_count+1;
				tables[c$id$orig_h]$_404count=tables[c$id$orig_h]$_404count+1;
				add tables[c$id$orig_h]$_url[c$http$uri];
				
				}
			else
				{
				tables[c$id$orig_h]$_count=tables[c$id$orig_h]$_count+1;
				}
			
			}
		
		}
	else
		{
		if(code == 404)
			{
			local y:set[string]={c$http$uri};
			local x=rec($t1=current_time(),$_count=1,$_404count=1,$_url=y);
			tables[c$id$orig_h]=x;
			}
		else
			{
			local tem:set[string];
			local xx=rec($t1=current_time(),$_count=1,$_404count=0,$_url=tem);
			tables[c$id$orig_h]=xx;
			

			}
		}	
	}
	
event zeek_done()
	{
	for (key in tables)
		{
		local xxx:count=0;
		for (key2 in tables[key]$_url)
			{
			xxx=xxx+1;
			}
		if (tables[key]$_404count > 2)
			{
			if ( tables[key]$_404count/tables[key]$_count > 0.2)
				{
				if( xxx/tables[key]$_404count > 0.5)
					{
					print fmt("%s is a scanner with %d scan attemps on %d urls",key,tables[key]$_404count,xxx);
					}
				}
			}
		}
	}
