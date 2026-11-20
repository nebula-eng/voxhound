"""Application-layer dissectors.

Each module is independent and duck-typed against
:class:`~voxhound.app.base.AppSession`; :mod:`registry` decides which one gets a
given stream or datagram.
"""
