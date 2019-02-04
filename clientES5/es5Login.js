    $("#btnGerar").on('click', function() {
      gerar();
    });
    var lastsecret;
    // script específico para manipulação deste HTML
    // cria a chave, altera o QR-CODE e apresenta o modal
	// Acionado pelo botão
    function gerar() {
      var senha = $('#senha').val();
      var user = $('#user').val();
      var dado = localStorage.getItem("TOTPKey" + user); // obtém a chave do TOTP em formato base32 que o cadastro criptografou e salvou
      if (!dado) {
        $('#resultado').text('Usuário inexistente!');
        $('#modal').modal('show');
      }
      var prom = decrypt(senha, dado); // descriptografa a chave do TOTP
      prom.then(secret => {
        console.log(secret); // chave
        createTOTPs(secret, showGenerateOTPs);
        lastsecret = secret;
        $('#totp').val('');
        $('#avisoTimer').val('Nova senha será gerada em: aguarde');
        $('#qrModal').modal('show');
        setInterval(timer, 1000);
      })
      .catch(function(err){
        console.error(err);
        $('#resultado').text('Erro!');
        $('#modal').modal('show');
      });;
    }
    function showGenerateOTPs(totps) {
      $('#totp').val(totps[1]);
    }
    $('#qrModal').on('hidden.bs.modal', function (e) {
      // cancela o timer
      var max = setTimeout(function(){},1);
        for (var i = 1; i <= max ; i++) {
            window.clearInterval(i);
            window.clearTimeout(i);
        }
    });
    function timer()
    {
      var epoch = Math.round(new Date().getTime() / 1000.0);
      var countDown = 30 - (epoch % 30);
      if (epoch % 30 == 0) createTOTPs(lastsecret, showGenerateOTPs);
      $('#avisoTimer').text('Nova senha será gerada em: ' + countDown);
    }
