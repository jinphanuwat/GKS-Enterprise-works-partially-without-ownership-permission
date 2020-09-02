<?php $__env->startSection('content'); ?>
<div class="container">
    <div>
        <h2>GKS ENTERPRISE<h2>
        <br>
        <h2>UPDATE COMPANY PROFILE</h2>
        <br>
        <form action="<?php echo e(route('fileUpload')); ?>" method="post" enctype="multipart/form-data">
        <?php echo csrf_field(); ?>
            <?php if($message = Session::get('success')): ?>
            <div class="alert alert-success">
                <strong><?php echo e($message); ?></strong>
            </div>
          <?php endif; ?>

          <?php if(count($errors) > 0): ?>
            <div class="alert alert-danger">
                <ul>
                    <?php $__currentLoopData = $errors->all(); $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $error): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                      <li><?php echo e($error); ?></li>
                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                </ul>
            </div>
          <?php endif; ?>
            <div class = "form-group">
                <label>Company Name</label>
                <input type ="text" name="company_name" class="form-control" value="Company Name">
            </div>
            <br>
            <div class = "form-group">
                <label>Contact Name</label>
                <input type ="text" name="contact_name" class="form-control" value="Contact Name">
                </div>
            <br>
            <div class = "form-group">
                <label>EMAIL</label>
                <input type ="text" name="email_new" class="form-control" value="name@name.com">
            </div>
            <br>
            <div class = "form-group">
                <label>Phone</label>
                <input type ="text" name="phone" class="form-control" value="Phone">
            </div>
            <br>
            <div class="form-group">
                <label for="company_file">Company Registration File:</label>
                <input type="file" class="form-control-file" id="company_file">
            </div>
            <br>
            <div class = "form-group">
                <label>Address</label>
                <input type ="text" name="address" class="form-control" value="Location">
            </div>
            <br>
            <div class = "form-group">
                <iframe
                width="600" height="250" frameborder="0" style="border:0" src="https://www.google.com/maps/embed/v1/place?key=AIzaSyDsJ01Kun6Kz-34DhfJKeok78hro6Nnru0&q=current+location">
                </iframe>
            </div>
            <br>
        
            </div class = "form-group">
                <button type="submit" name="submit" class="btn btn-primary btn-block mt-4">
                Update Info
                </button>

            <div>
        </form>
        <br>
        Contact Admin:
    
        </div class = "form-group">
        <input type="submit" value="chat with admin">
        <div>

        
    </div>
</div>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', \Illuminate\Support\Arr::except(get_defined_vars(), ['__data', '__path']))->render(); ?><?php /**PATH C:\xampp\htdocs\GKS\resources\views//home.blade.php ENDPATH**/ ?>