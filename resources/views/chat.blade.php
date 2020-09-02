<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="csrf-token" content="{{ csrf_token() }}">
        

        <title>Chat</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Nunito:200,600" rel="stylesheet">
        <link ref="stylesheet" href="{{ asset('css/app.css') }}">
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
        <style>
            .list-group{
                overflow-y: scroll;
                height: 600px
            }
        </style>

    </head>
    <body>
      
        <div class="container">
        <div class="row" id="app">
        <div class="list-group offset-4 col-4 offset-sm-1 col-sm-10">
        <ul class="list-group"v-chat-scroll>
            <li class="list-group-item active">Chat Room<span class="badge-pill badge-danger">@{{ numberOfUsers }}</span></li>
            <div class="badge badge-pill badge-primary">@{{ typing }}</div>
            <message v-for="value, index in chat.message" :key=value.index color="success" :user=chat.user[index] :color=chat.color[index] :time=chat.time[index]>
            @{{ value }}
            </message>
        </ul>
        <input type="text" class="form-control" placeholder ="type your messages here..." v-model="message" @keyup.enter="send">
        <br>
        <a href ="" class ="btn btn-warning btn-sm" @click.prevent="deleteSession">Delete Chats</a>
        </div>
        </div>
        </div>
        <script src="{{ asset('js/app.js') }}"></script>
        <script src="https://cdn.jsdelivr.net/npm/vue-chat-scroll/dist/vue-chat-scroll.min.js"></script>
    </body>
</html>