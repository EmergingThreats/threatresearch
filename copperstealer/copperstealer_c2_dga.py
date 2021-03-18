from datetime import date, timedelta
import hashlib

daily_seeds = [
    {'seed': 'changenewsys', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'exchangework', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'DavidCopperfield', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'FrankLin', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'Vindiesel', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'WebGL', 'suffix': '.club', 'date_format': '%Y%m%d', 'additional_appends': []},
    {'seed': 'hellojackma', 'suffix': '.xyz', 'date_format': '%Y%m%d', 'additional_appends': []},
]

monthly_seeds = [
    {'seed': 'hellojackma', 'suffix': '.com', 'date_format': '%Y%m', 'additional_appends': ['', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
     }
]

start_date = date(2000, 1, 1)
end_date = date(2050, 2, 3)


def build_details(entry, target_date):

    if entry.get('additional_appends'):
        for append in entry.get('additional_appends'):
            c2_string = f'{entry.get("seed")}{target_date.strftime(entry.get("date_format"))}{append}'

            c2_md5 = hashlib.md5(c2_string.encode()).hexdigest()
            domain_base = c2_md5[8:-8]

            c2_details = {
                'date': target_date.strftime(entry.get('date_format')),
                'seed': entry.get('seed'),
                'domain': f"{domain_base}{entry.get('suffix')}"
            }

            yield c2_details

    else:

        c2_string = f'{entry.get("seed")}{target_date.strftime(entry.get("date_format"))}'

        c2_md5 = hashlib.md5(c2_string.encode()).hexdigest()
        domain_base = c2_md5[8:-8]

        c2_details = {
            'date': target_date.strftime(entry.get('date_format')),
            'seed': entry.get('seed'),
            'domain': f"{domain_base}{entry.get('suffix')}"
        }

        yield c2_details


final_entries = []
for day in range(int((end_date - start_date).days)):
    target_date = start_date + timedelta(days=day)

    for entry in daily_seeds:
        for result in build_details(entry, target_date):
            if result not in final_entries:
                final_entries.append(result)

    if target_date == target_date.replace(day=1):
        # we have the first day of the month?
        for entry in monthly_seeds:
            for result in build_details(entry, target_date):
                if result not in final_entries:
                    final_entries.append(result)

for final_entry in final_entries:
    print(f"{final_entry.get('seed')},{final_entry.get('date')},{final_entry.get('domain')}")
