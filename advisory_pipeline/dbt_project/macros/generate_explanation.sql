{% macro generate_explanation(reason_code, evidence) %}
    case {{ reason_code }}
        when 'CSV_OVERRIDE' then
            concat('Marked as not applicable by Echo security team. Reason: ',
                   coalesce({{ evidence }}['csv_reason'], 'Internal policy'),
                   '.')
        when 'NVD_REJECTED' then
            'This CVE has been rejected by the National Vulnerability Database.'
        when 'UPSTREAM_FIX' then
            concat('Fixed in version ',
                   coalesce({{ evidence }}['fixed_version'], 'unknown'),
                   '. Fix available from upstream.')
        when 'NEW_CVE' then
            'Recently published CVE under analysis. Awaiting upstream signals.'
        when 'AWAITING_FIX' then
            'No fix currently available upstream. Monitoring for updates.'
        else
            'Status determined by enrichment pipeline.'
    end
{% endmacro %}
