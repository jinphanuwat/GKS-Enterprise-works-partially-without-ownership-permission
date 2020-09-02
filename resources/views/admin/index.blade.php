@extends('admin.layout')
 
@section('content')
    <div class="row">
        <div class="col-sm-12">
            <div class="pull-left">
                <h2>Listing all users...</h2>
            </div>

        <div class="col-sm-12">
            @if(session()->get('success'))
                <div class="alert alert-success">
                    {{ session()->get('success') }}
                </div>
            @endif
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
        @foreach ($users as $user)
        <tr>
            <td>{{ $user->id }}</td>
            <td>{{ $user->name }}</td>
            <td>{{ $user->total_score }}</td>
            <td>{{ $user->email }}</td>
            <td>   

                    <a href="{{ route('edit',$row->id) }}" class ="btn btn-primary">Edit</a>
            </td>
            <td>
                    <form onclick="return confirm('Delete?');" action=" {{ route('delete', $row->id) }}" method ="post">
                    @csrf
                    @method('DELETE')
                    <button type="submit" class="btn btn-danger">Delete</button>
                    </form>
            </td>

        </tr>
        @endforeach

        <td>
                    </div class = "form-group">
                    <input type="submit" value="chat with admin">
                    <div>
        </td>
        </tbody>
        </table>

        </div>
    </div> 
@endsection