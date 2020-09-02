@extends('adminlte::page')

@section('content')
<div class="row">
<div class="col-sm-12">
    <h2 class="display-4">GKS ENTERPRISE: List of Staff Contacts</h2>    
    <div>
    <a style="margin: 19px;" href="{{ route('create') }}" class="btn btn-primary">Create new contact</a>
    <a href ="{{ url('chat') }}">Enter Chat Room</a>
    </div> 
    <table class="table table-striped">
    <thead>
        <tr>
          <td>ID</td>
          <td>Name</td>
          <td>TOTAL SCORE</td>
          <td>Email</td>
          <td colspan = 3>Actions</td>
        </tr>
    </thead>
    @foreach ($contacts as $contact)
        <tr>
            <td>{{ $contact->id }}</td>
            <td>{{ $contact->name }}</td>
            <td>{{ $contact->total_score }}</td>
            <td>{{ $contact->email }}</td>
            <td>

                    <a title="edit" href="{{ route('edit', ['id' => $contact->id]) }}"><i class ="small material-icons"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48px" height="48px"><path fill="#E57373" d="M42.583,9.067l-3.651-3.65c-0.555-0.556-1.459-0.556-2.015,0l-1.718,1.72l5.664,5.664l1.72-1.718C43.139,10.526,43.139,9.625,42.583,9.067"/><path fill="#FF9800" d="M4.465 21.524H40.471999999999994V29.535H4.465z" transform="rotate(134.999 22.469 25.53)"/><path fill="#B0BEC5" d="M34.61 7.379H38.616V15.392H34.61z" transform="rotate(-45.02 36.61 11.385)"/><path fill="#FFC107" d="M6.905 35.43L5 43 12.571 41.094z"/><path fill="#37474F" d="M5.965 39.172L5 43 8.827 42.035z"/></svg></i></a>
            </td>
            <td>
                    <form method="post" onclick="return confirm('Delete?');" action=" {{ route('delete', $contact->id) }}">  
                    @csrf @method('DELETE')
                    <i class="small material-icons">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48px" height="48px">
                    <path fill="#F44336" d="M21.5 4.5H26.501V43.5H21.5z" transform="rotate(45.001 24 24)"/>
                    <path fill="#F44336" d="M21.5 4.5H26.5V43.501H21.5z" transform="rotate(135.008 24 24)"/>
                    </svg></i></form>
            </td>

        </tr>
        @endforeach
    

    </table>
    {{ $contacts->links() }}
<div>
</div>
@endsection