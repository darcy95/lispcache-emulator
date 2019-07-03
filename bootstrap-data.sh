# Retrieving globally announced BGP prefixes
echo "===============================================";
echo "= Downloading globally announced BGP prefixes =";
echo "===============================================";
wget -O- -q http://data.caida.org/datasets/routing/routeviews-prefix2as/2019/07/routeviews-rv2-20190701-1200.pfx2as.gz | zcat | awk '{ print $1"/"$2,$3; }' > bgp-prefixes

wc -l bgp-prefixes | cut -d " " -f 1 | awk '{ print $1,"prefixes are stored in bgp-prefixes" }'

# other sources
#  http://thyme.apnic.net/london/data-ASnet-detail
