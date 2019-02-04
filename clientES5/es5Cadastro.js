    $("#btnCadastrar").on('click', function() {
      salvaTOTPKey();
    });
    
    // script específico para manipulação deste HTML
    function salvaTOTPKey() {
      // versão simplificada, não valida a senha digitada
      var senha = $('#senha').val();
      var user = $('#user').val();
      var secret = $('#secretHex').val();
      var prom = encrypt(senha, secret);
      prom.then(dado => {
        console.log(dado);
        localStorage.setItem("TOTPKey" + user, dado);
        $('#resultado').text('Sucesso!');
        $('#modal').modal('show');
      })
      .catch(function(err){
        console.error(err);
        $('#resultado').text('Erro!');
        $('#modal').modal('show');
      });;
    }
