 
<?php $__env->startSection('content'); ?>
<?php echo Form::open(['action' =>'ContactController@store', 'method' => 'POST','files'=>true]); ?>

    
<div class="col-md-6">
        
        
        <div class="form-group required">
           <?php echo Form::label("NAME"); ?>

           <?php echo Form::text("name", null ,["class"=>"form-control","required"=>"required"]); ?>

       </div>

        <div class="form-group required">
           <?php echo Form::label("EMAIL"); ?>

           <?php echo Form::text("email", null ,["class"=>"form-control","required"=>"required"]); ?>

       </div>

        <div class="form-group required">
           <?php echo Form::label("TOTAL SCORE"); ?>

           <?php echo Form::text("total_score", null ,["class"=>"form-control","required"=>"required"]); ?>

       </div>



   <div class="well well-sm clearfix">
       <button class="btn btn-success pull-right" title="Save" type="submit">Create</button>
   </div>
</div>

<?php echo Form::close(); ?>

<?php $__env->stopSection(); ?>
<?php echo $__env->make('layouts.app', \Illuminate\Support\Arr::except(get_defined_vars(), ['__data', '__path']))->render(); ?><?php /**PATH C:\xampp\htdocs\GKS\resources\views/contacts/edit.blade.php ENDPATH**/ ?>