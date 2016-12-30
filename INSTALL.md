Installation instructions
=========================

Concerto depends on the following OCaml libraries:

* Lwt (>= 2.4.3)
* Calendar
* Cryptokit (>= 1.10)
* OUnit (for some tests)
* Yojson
* Parsifal

You first need to compile Parsifal, following the installation
instructions. You must make sure the parsifal_core, parsifal_crypto
and parsifal_ssl libraries are available from the OCAMLPATH path.

You can do this either by using the default library directory to
install parsifal when launching make install for parsifal (here an
example with a Debian system):

    # LIBDIR=/usr/lib/ocaml make install

or by adding the correct path to the OCAMLPATH variable

    # make install     # /usr/local/lib/ocaml will be used by default
    $ export OCAMLPATH=$OCAMLPATH:/usr/local/lib/ocaml

Then you must install yojson, either using apt-get, opam or your
package manager, depending on your setup:

    # apt-get install libyojson-ocaml-dev

    % opam install yojson

Assuming you want to compile parsifal in the ~/concerto directory, you
can then type in the following commands:

    % cd
    % git clone https://github.com/ANSSI-FR/concerto
    % cd concerto
    % make

Notes
-----

With opam, only OCaml 4.02.3 has been tested. Other versions could
work, but compilation will fail with the latest one, due to the
bytes/string evolution in recent versions.