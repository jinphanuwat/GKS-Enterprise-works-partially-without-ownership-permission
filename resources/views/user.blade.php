@extends('layouts.app')

@section('content')
<div class="container">
    <div>
        <h2>GKS ENTERPRISE<h2>
        <a href = "">Go to Profile</a>
        <br>
        <h2>UPDATE COMPANY PROFILE</h2>
        <br>
        <form action="{{action ('CompanyController@store')}}" method="post" enctype="multipart/form-data">
        @csrf
            @if ($message = Session::get('success'))
            <div class="alert alert-success">
                <strong>{{ $message }}</strong>
            </div>
          @endif

          @if (count($errors) > 0)
            <div class="alert alert-danger">
                <ul>
                    @foreach ($errors->all() as $error)
                      <li>{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
          @endif
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
        <a href = "{{ url('chat') }}"><svg height="50pt" viewBox="0 0 100 50" width="100pt" xmlns="http://www.w3.org/2000/svg"><path d="m512 256c0 141.386719-114.613281 256-256 256s-256-114.613281-256-256 114.613281-256 256-256 256 114.613281 256 256zm0 0" fill="#ffd400"/><path d="m512 256c0-9.320312-.511719-18.519531-1.480469-27.582031l-121.179687-121.175781-264.972656 223.445312 52.492187 52.496094-39.859375 55.816406 67.890625 67.890625c16.515625 3.347656 33.605469 5.109375 51.109375 5.109375 141.386719 0 256-114.613281 256-256zm0 0" fill="#fdba12"/><path d="m256 60c-103.339844 0-187.109375 70.84375-187.109375 158.234375 0 49.167969 26.515625 93.09375 68.109375 122.117187v98.648438l100.277344-63.3125c6.160156.515625 12.402344.785156 18.722656.785156 103.339844 0 187.109375-70.84375 187.109375-158.238281 0-87.390625-83.769531-158.234375-187.109375-158.234375zm0 0" fill="#4a7aff"/><path d="m256 60c-.351562 0-.703125.011719-1.054688.011719v316.449219c.351563.003906.703126.011718 1.054688.011718 103.339844 0 187.109375-70.84375 187.109375-158.238281 0-87.390625-83.769531-158.234375-187.109375-158.234375zm0 0" fill="#0053bf"/><path d="m279.371094 291.347656-58.074219-61.933594-113.296875 61.933594 124.632812-132.308594 59.480469 61.933594 111.886719-61.933594zm0 0" fill="#fff"/><path d="m404 159.039062-111.886719 61.933594-37.167969-38.703125v83.023438l24.425782 26.054687zm0 0" fill="#dce1eb"/></svg></a>
        <div>

        
    </div>
</div>
@endsection
