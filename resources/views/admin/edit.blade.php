@extends('blogs.layout')
   
@section('content')
    <div class="row">
        <div class="col-lg-12 margin-tb">
            <div class="pull-left">
                <h2>Update User</h2>
            </div>
            <div class="pull-right">
                <a class="btn btn-primary" href="{{ route('index') }}"> Back</a>
            </div>

    @if ($errors->any())
        <div class="alert alert-danger">
            <strong>Warning!</strong> Please check input field code<br><br>
            <ul>
                @foreach ($errors->all() as $error)
                    <li>{{ $error }}</li>
                @endforeach
            </ul>
        </div>
        <br />
    @endif
  
        <form action="{{ route('update',$data->id) }}" method="POST">
        @csrf
        @method('PATCH')
   
        
                <div class="form-group">
                    <strong>NAME:</strong>
                    <input type="text" name="name" value="{{ $user->name }}" class="form-control" placeholder="Name"/>
                </div>
            

                <div class="form-group">
                    <strong>TOTAL SCORE:</strong>
                    <input type="text" name="total_score" value="{{ $user->total_score }}" class="form-control" placeholder="total_score"/>
                </div>
            
        
                <div class="form-group">
                    <strong>EMAIL:</strong>
                    <input type="text" name="email" value="{{ $user->email}}" class="form-control" placeholder="email"/>
                </div>
        
      
              <button type="submit" class="btn btn-primary">Update</button>

        </form>
        </div>
    </div>
   
@endsection