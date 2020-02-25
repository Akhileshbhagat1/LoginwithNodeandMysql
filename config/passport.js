var LocalStrategy = require('passport-local').Strategy;
var mysql = require('mysql');
var bcrypt = require('bcrypt');
var dbconfig = require('./database');
var connection = mysql.createConnection(dbconfig.connections);

connection.query('USE ' + dbconfig.database );

module.exports = function(passport){
    passport.serializeUser(function(user, done){
        done(null, user.id)
    });
    
    passport.deserializeUser(function(id, done){
        connection.query('SELECT * FROM user WHERE id = ?', [id],
            function(err, rows){
                done(err, rows[0]);
            });
    });

    passport.use(
        'local-signup',
        new LocalStrategy({
            usernameField: 'username',
            passwordField : 'password',
            passReqToCallback: true
        },
        function(req, username, password, done){
            connection.query("SELECT * FROM user WHERE username = ?", 
            [username], function (err, rows){
                if(err)
                    return done(err);
                if(rows.length){
                    return done(null, false, req.flash('signupMessage', 'User already exist'));
                }else{
                    var newUserMysql = {
                        username : username,
                        password : bcrypt.hashSync(password, null, null)
                    };

                    var insertQuery = "INSERT INTO user (username, password) values (?, ?)";

                    connection.query(insertQuery, [newUserMysql.username, newUserMysql.password],
                        function(err, rows){
                            newUserMysql.id = rows.insertId;

                            return done(null, newUserMysql);
                        });
                }
            });
        }) 
    );
            passport.use(
                'local-login',
                new LocalStrategy({
                    usernameField: 'username',
                    passwordField: 'password',
                    passReqToCallback: true
                },
                function(req, username, password, done){
                    connection.query("SELECT * FROM user WHERE username = ? ", [username],
                    function(err, rows){
                        if(err)
                            return done(err);
                        if (!rows.length){
                            return done(null, false, req.flash('loginMessage', 'No user found'));
                        }
                        console.log("it is no my fault ",!bcrypt.compareSync(password, rows[0].password))
                        if (!bcrypt.compare(password, rows[0].password))
                            return done(null, false, req.flash('loginMessage', 'wrong Password'));
                        return done(null, rows[0])
                    });
                    
                })
                
            );
};

