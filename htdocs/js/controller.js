/*

 controller.js -- The GBrowse controller object

 Lincoln Stein <lincoln.stein@gmail.com>
 $Id: controller.js,v 1.12 2008-07-09 22:16:54 lstein Exp $

*/

var Controller;        // singleton
var SegmentObservers      = new Hash();
var UpdateOnLoadObservers = new Hash();
var TrackImages           = new Hash();


var GBrowseController = Class.create({

	initialize: function () {
        this.periodic_updaters = new Array();
	},

	updateCoordinates: function (action) {

        //Grey out image
        TrackImages.keys().each(
            function(image_id) {
                $(image_id).setOpacity(0.3);
            }
        );

        this.periodic_updaters[this.count] = this.count;
	    new Ajax.Request('#',{
		    method:     'post',
   		    parameters: {navigate: action},
		    onSuccess: function(transport) {
                var results    = transport.responseJSON;
                var segment    = results.segment;
                var track_keys = results.track_keys;
                var overview_scale_bar_hash = results.overview_scale_bar;
                var detail_scale_bar_hash = results.detail_scale_bar;

                update_scale_bar(overview_scale_bar_hash);
                update_scale_bar(detail_scale_bar_hash);

                SegmentObservers.keys().each(
                              function(e) {
                              $(e).fire('model:segmentChanged',{segment: segment, track_keys: track_keys});
                              }
                              );
		    }
            
		}
		);
	}
    }
);

function initialize_page () {
    Controller = new GBrowseController; // singleton

    //event handlers
    var elements = ['page_title','span'];
    elements.each(function(el) {
	    SegmentObservers.set(el,1);
	    $(el).observe('model:segmentChanged',function(event) {
		    new Ajax.Updater(this,'#',{
			    parameters: {update: this.id}
		    });
		}
		)
    });
    new Ajax.Request('#',{
        method:     'post',
        parameters: {first_render: 1},
        onSuccess: function(transport) {
            var results = transport.responseJSON;
            var segment = results.segment;
            var track_keys = results.track_keys;
            UpdateOnLoadObservers.keys().each(
                function(e) {
                    $(e).fire('model:segmentChanged',{segment: segment, track_keys: track_keys});
                }
            );
        }
    }
    );

}

function register_track ( detail_div_id,detail_image_id,track_type ) {
    TrackImages.set(detail_image_id,1);
    if (track_type=="scale_bar"){
        return;
    }
    SegmentObservers.set(detail_div_id,1);
    UpdateOnLoadObservers.set(detail_div_id,1);
    //alert("registering track "+detail_div_id);
    $(detail_div_id).observe('model:segmentChanged',function(event) {
	    var track_key = event.memo.track_keys[detail_div_id];
        //alert ("track_changed "+detail_div_id);
        if (track_key){
            if (Controller.periodic_updaters[detail_div_id]){
                Controller.periodic_updaters[detail_div_id].stop();
            }

            track_image = document.getElementById(detail_image_id);
            Controller.periodic_updaters[detail_div_id] = 
                new Ajax.PeriodicalUpdater(
                    detail_div_id,
                    '#',
                    { 
                        frequency:1, 
                        decay:1.5,
                        method: 'post',
                        parameters: {
                            track_key:      track_key,
                            retrieve_track: detail_div_id,
                            image_width:    track_image.width,
                            image_height:   track_image.height,
                            image_id:       detail_image_id,
                        },
                        onSuccess: function(transport) {
                            //alert ("success "+detail_div_id +" "+transport.responseText.substring(0,10));
                            detail_div = document.getElementById(detail_div_id);
                            if (transport.responseText.substring(0,18) == "<!-- AVAILABLE -->"){
                                detail_div.innerHTML = transport.responseText;
                                Controller.periodic_updaters[detail_div_id].stop();
                                reset_after_track_load();
                            }
                            else if (transport.responseText.substring(0,16) == "<!-- EXPIRED -->"){
				Controller.periodic_updaters[detail_div_id].stop();
                                reset_after_track_load();
                            }
                            else {
                                // Manually stop the updater from modifying the element
                                var p_updater = Controller.periodic_updaters[detail_div_id];
                                var decay = p_updater.decay;
                                p_updater.stop();
                                p_updater.decay = decay * p_updater.options.decay;
                                p_updater.timer = p_updater.start.bind(p_updater).delay(p_updater.decay * p_updater.frequency);
                            }
                        }
                     }
                );
        }
	}
	);
}

// This may be a little overkill to run these after every track update but
// since there is no "We're completely done with all the track updates for the
// moment" hook, I don't know of another way to make sure the tracks become
// draggable again
function reset_after_track_load ( ) {
    create_drag('overview_panels','track');
    create_drag('detail_panels','track');
}

function update_scale_bar (bar_obj ) {
    var image_id = bar_obj.image_id;
    $(image_id).src = bar_obj.url;
    $(image_id).height = bar_obj.height;
    $(image_id).width = bar_obj.width;
    $(image_id).setOpacity(1);
}
