"""Traffic counter rules shared by the panel poll.

Bytes already added to a user are stored with the counter that produced
them. A later poll charges only the difference. A new process generation
(systemd epoch change, or a counter that went backwards) is added from zero
because that counter no longer includes the old bytes. A failed stats read
must not call this function: the caller keeps the previous cursor.
"""


def _int(value):
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def counter_delta(previous, total, previous_epoch=None, epoch=None):
    previous = _int(previous)
    total = _int(total)
    prev_epoch = "" if previous_epoch is None else str(previous_epoch)
    new_epoch = "" if epoch is None else str(epoch)
    if prev_epoch and new_epoch and prev_epoch != new_epoch:
        return total
    if total < previous:
        return total
    return total - previous
