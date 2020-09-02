@extends('layouts.app')

@section('content')
<div class="container">
     @foreach $companies as $company
     <td>$company->name</td>
     <td>$company->address</td>
     <td>$company->email</td>
     <td>$company->contact_name</td>
     


     @endforeach
</div>
@endsection
