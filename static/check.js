function start(){
	$(document).ready(check);

	function check(){
		$("button").click(function(event){
			var url = $SCRIPT_ROOT + '/check';
			var selectedId = $(this).attr('id');
			var selectedValue = $("select." + selectedId).val();
			$.getJSON(url,
				id:selectedId,
				value:selectedValue
			});



		}
	}