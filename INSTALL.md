Installation instructions
=========================

Concerto depends on the following OCaml libraries:

* Lwt
* Calendar
* Cryptokit
* OUnit (for some tests)
* Yojson
* Parsifal

You will also need Ocamlbuild to compile concerto.

Finally, we assume your system has a python interpreter, pygraphviz,
flask and sqlite3. On Debian, these dependencies are installed using
the following command:

    # apt-get install python python-pygraphviz python-flask sqlite3


Compilation environment
-----------------------

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

    # apt-get install libyojson-ocaml-dev ocamlbuild

or

    % opam install yojson


Compilation instructions
------------------------

Assuming you want to compile parsifal in the ~/concerto directory, you
can then type in the following commands:

    % cd
    % git clone https://github.com/picty/concerto
    % cd concerto
    % make


Notes
-----

These instructions have been tested with Debian Buster, and with opam
1.2 (and OCaml 4.05.0 and 4.06.0).

It could also work with other versions of opam and of the compiler.
