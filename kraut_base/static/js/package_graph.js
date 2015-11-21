var w = parseInt(d3.select('#tree-container').style('width'))-30;
var h = (w * .5)-120;
var n = 50;
var adjustme = 170;
var keyi = true, keyo = true, keyp = true;
var focus_node = null, highlight_node = null;
var text_center = false;
var outline = false;
var min_score = 0;
var max_score = 1;
var color = d3.scale.linear().domain([min_score, (min_score+max_score)/2, max_score]).range(["lime", "yellow", "red"]);
var highlight_color = "#f1c40f";
var highlight_trans = 0.1;
var size = d3.scale.pow().exponent(1).domain([1,100]).range([8,24]);
var force = d3.layout.force()
  .linkDistance(h/6)
  .charge(-400)
  .size([w,h]);

var default_node_color = "#34495e";
var default_link_color = "#2c3e50";
var nominal_base_node_size = 8;
var nominal_text_size = 10;
var max_text_size = 24;
var nominal_stroke = 1.5;
var max_stroke = 4.5;
var max_base_node_size = 36;
var min_zoom = 0.1;
var max_zoom = 7;
var svg = d3.select("#tree-container").append("svg");
var zoom = d3.behavior.zoom().scaleExtent([min_zoom,max_zoom])
var g = svg.append("g");
svg.style("cursor","move");
var loading = svg.append("text")
    .attr("x", 60)
    .attr("y", 60)
    .attr("dy", ".35em")
    .style("text-anchor", "middle")
    .text("Loading ...");

var package_id = document.getElementById("package_id").value;

d3.json("/api/packagesd3/tree/"+package_id+"/", function(error, graph) {
    var linkedByIndex = {};
    graph.links.forEach(function(d) {
        linkedByIndex[d.source + "," + d.target] = true;
    });
    function isConnected(a, b) {
        return linkedByIndex[a.index + "," + b.index] || linkedByIndex[b.index + "," + a.index] || a.index == b.index;
    }
    function hasConnections(a) {
        for (var property in linkedByIndex) {
            s = property.split(",");
            if ((s[0] == a.index || s[1] == a.index) && linkedByIndex[property]) return true;
        }
        return false;
    }

    force.nodes(graph.nodes).links(graph.links);

    setTimeout(function() {
        force.start();
        for (var i = n * n; i > 0; --i) force.tick();
        force.stop();
        loading.remove();
    }, 10);
    
    var link = g.selectAll(".link")
        .data(graph.links)
        .enter().append("line")
        .attr("class", "link")
        .style("stroke-width",nominal_stroke)
        .style("stroke", function(d) { return default_link_color; });

    var node = g.selectAll(".node")
        .data(graph.nodes)
        .enter().append("g")
        .attr("class", "node")
        .call(force.drag);

    node.on("dblclick.zoom", function(d) { d3.event.stopPropagation();
        var dcx = (w/2-d.x*zoom.scale());
        var dcy = ((h-10)/2-d.y*zoom.scale());
        zoom.translate([dcx,dcy]);
        g.attr("transform", "translate("+ dcx + "," + dcy  + ")scale(" + zoom.scale() + ")");
    });
    
    var tocolor = "fill";
    var towhite = "stroke";
    if (outline) {
        tocolor = "stroke"
        towhite = "fill"
    }
    
    var circle = node.append("path")
        .attr("d", d3.svg.symbol()
        .size(function(d) { return Math.PI*Math.pow(size(d.size)||nominal_base_node_size,2); })
        .type(function(d) { return d.type; }))
        .style(tocolor, function(d) {
            if (isNumber(d.score) && d.score==1) return "#9b59b6";
            else if (isNumber(d.score) && d.score==0.6) return "#3498db";
            else if (isNumber(d.score) && d.score==0.3) return "#f1c40f";
            else if (isNumber(d.score) && d.score==0.5) return "#2980b9";
            else if (isNumber(d.score) && d.score==0.7) return "#e74c3c";
            else return default_node_color; 
        })
        .style("stroke-width", nominal_stroke)
        .style(towhite, "white");
                
  var text = g.selectAll(".text")
    .data(graph.nodes)
    .enter().append("text")
    .attr("dy", ".35em")
    .style("font-size", nominal_text_size + "px")

    if (text_center)
     text.text(function(d) { return d.id; })
    .style("text-anchor", "middle");
    else 
    text.attr("dx", function(d) {return (size(d.size)||nominal_base_node_size);})
    .text(function(d) { return '\u2002'+d.id; });

    node.on("mouseover", function(d) {
        set_highlight(d);
    })
    .on("mousedown", function(d) { 
        d3.event.stopPropagation();
        focus_node = d;
        set_focus(d)
        if (highlight_node === null) set_highlight(d)
    }).on("mouseout", function(d) {
        exit_highlight();
    });

    d3.select(window).on("mouseup", function() {
        if (focus_node!==null)
        {
            focus_node = null;
            if (highlight_trans<1)
            {
                circle.style("opacity", 1);
                text.style("opacity", 1);
                link.style("opacity", 1);
            }
        }
        if (highlight_node === null) exit_highlight();
    });

    function exit_highlight() {
        highlight_node = null;
        if (focus_node===null)
        {
            svg.style("cursor","move");
            if (highlight_color!="white")
            {
                circle.style(towhite, "white");
                text.style("font-weight", "normal");
                link.style("stroke", function(o) {return (isNumber(o.score) && o.score>=0)?color(o.score):default_link_color});
            }
        }
    }

    function set_focus(d) {   
        if (highlight_trans<1)
        {
            circle.style("opacity", function(o) {
                return isConnected(d, o) ? 1 : highlight_trans;
            });

            text.style("opacity", function(o) {
                return isConnected(d, o) ? 1 : highlight_trans;
            });
            
            link.style("opacity", function(o) {
                return o.source.index == d.index || o.target.index == d.index ? 1 : highlight_trans;
            });     
        }
    }

    function set_highlight(d) {
        svg.style("cursor","pointer");
        if (focus_node!==null) d = focus_node;
        highlight_node = d;
        if (highlight_color!="white")
        {
            circle.style(towhite, function(o) { return isConnected(d, o) ? highlight_color : "white";});
            text.style("font-weight", function(o) { return isConnected(d, o) ? "bold" : "normal";});
            link.style("stroke", function(o) {
              return o.source.index == d.index || o.target.index == d.index ? highlight_color : ((isNumber(o.score) && o.score>=0)?color(o.score):default_link_color);

            });
        }
    }
    
    zoom.on("zoom", function() {
        var stroke = nominal_stroke;
        if (nominal_stroke*zoom.scale()>max_stroke) stroke = max_stroke/zoom.scale();
        link.style("stroke-width",stroke);
        circle.style("stroke-width",stroke);
       
        var base_radius = nominal_base_node_size;
        if (nominal_base_node_size*zoom.scale()>max_base_node_size) base_radius = max_base_node_size/zoom.scale();
        circle.attr("d", d3.svg.symbol()
            .size(function(d) { return Math.PI*Math.pow(size(d.size)*base_radius/nominal_base_node_size||base_radius,2); })
            .type(function(d) { return d.type; }))
        
        if (!text_center) text.attr("dx", function(d) { return (size(d.size)*base_radius/nominal_base_node_size||base_radius); });
    
        var text_size = nominal_text_size;
        if (nominal_text_size*zoom.scale()>max_text_size) text_size = max_text_size/zoom.scale();
        text.style("font-size",text_size + "px");
        g.attr("transform", "translate(" + d3.event.translate + ")scale(" + d3.event.scale + ")");
    });
     
    svg.call(zoom);     
    resize();
    d3.select(window).on("resize", resize);
      
    force.on("tick", function() {
        node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        text.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        link.attr("x1", function(d) { return d.source.x; })
            .attr("y1", function(d) { return d.source.y; })
            .attr("x2", function(d) { return d.target.x; })
            .attr("y2", function(d) { return d.target.y; });
        node.attr("cx", function(d) { return d.x; })
            .attr("cy", function(d) { return d.y; });
    });
  
    function resize() {
        var width = w, height = h;
        svg.attr("width", width).attr("height", height);
        force.size([force.size()[0]+(width-w-adjustme)/zoom.scale(),force.size()[1]+(height-h)/zoom.scale()]).resume();
        w = width;
        h = height;
    }

});


function isNumber(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

$(function () {
    $('[data-toggle="popover"]').popover()
});

$(document).ready(function(){
    $('[data-toggle="tooltip"]').tooltip();
});
