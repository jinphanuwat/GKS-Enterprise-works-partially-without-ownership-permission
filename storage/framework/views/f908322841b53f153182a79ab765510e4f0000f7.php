
 
<?php $__env->startSection('content'); ?>
    <div class="row">
        <div class="col-sm-12">
            <div class="pull-left">
                <h2>Listing all users...</h2>
            </div>

        <div class="col-sm-12">
            <?php if(session()->get('success')): ?>
                <div class="alert alert-success">
                    <?php echo e(session()->get('success')); ?>

                </div>
            <?php endif; ?>
        </div>

        <table class="table table-striped">
        <thead>
        <tr>
            <td>NO</td>
            <td>NAME</td>
            <td>TOTAL SCORE</td>
            <td>EMAIL</td>
            <td colspan = 3>Action</td>
        </tr>
        </thead>
         <tbody>
        <?php $__currentLoopData = $users; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $user): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
        <tr>
            <td><?php echo e($user->id); ?></td>
            <td><?php echo e($user->name); ?></td>
            <td><?php echo e($user->total_score); ?></td>
            <td><?php echo e($user->email); ?></td>
            <td>   

                    <a href="<?php echo e(route('edit',$row->id)); ?>" class ="btn btn-primary">Edit</a>
            </td>
            <td>
                    <form onclick="return confirm('Delete?');" action=" <?php echo e(route('delete', $row->id)); ?>" method ="post">
                    <?php echo csrf_field(); ?>
                    <?php echo method_field('DELETE'); ?>
                    <button type="submit" class="btn btn-danger">Delete</button>
                    </form>
            </td>

        </tr>
        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>

        <td>
                    </div class = "form-group">
                    <input type="submit" value="chat with admin">
                    <div>
        </td>
        </tbody>
        </table>

        </div>
    </div> 
<?php $__env->stopSection(); ?>
<?php echo $__env->make('admin.layout', \Illuminate\Support\Arr::except(get_defined_vars(), ['__data', '__path']))->render(); ?><?php /**PATH C:\xampp\htdocs\GKS\resources\views/admin/index.blade.php ENDPATH**/ ?>