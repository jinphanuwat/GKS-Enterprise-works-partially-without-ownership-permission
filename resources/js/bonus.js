$(document).ready(function() {
    $('.deleteform').click(function(evt){
            evt.preventDefault();
            var name=$(this).data("name");
            var form=$(this).closest("form");
            swal({
                title: "Do you need to delete this data? (คุณต้องการลบข้อมูลนี้หรือไม่?)",
                text: "If you delete it can not be undone! (ถ้าลบแล้วไม่สามารถกู้คืนได้) ",
                icon: "warning",
                buttons: true,
                dangerMode:true
            }).then((willDelete){
                if(willDelete) {
                    form.submit();
                }
            }); 
    });

});